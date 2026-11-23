use crate::{
    store::{HashPresence, PutClass},
    Capability, Limits, RelayError, RelayResult, RelayStore, Role, StoredResult,
};
use loki_relay_protocol::{
    nonce::ClaimProof,
    types::{CreationResult, Id32, Object, Page},
};
use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc as std_mpsc, Arc,
    },
    time::Duration,
};
use tokio::sync::{mpsc, oneshot};

pub const WRITER_QUEUE_CAPACITY: usize = 64;
const FRESH_QUEUE_LIMIT: usize = 62;
const CLASSIFY_QUEUE_CAPACITY: usize = 32;
const CLASSIFY_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone)]
pub struct DbHandle {
    sender: mpsc::Sender<Command>,
    stopping: Arc<AtomicBool>,
    root: Arc<PathBuf>,
    classify: std_mpsc::SyncSender<ClassifyJob>,
    classify_hash: std_mpsc::SyncSender<ClassifyJob>,
    fresh: Arc<AtomicUsize>,
}

pub struct DbReply<T>(oneshot::Receiver<RelayResult<T>>);
impl<T> DbReply<T> {
    pub async fn receive(self) -> RelayResult<T> {
        self.0.await.map_err(|_| RelayError::StorageUnavailable)?
    }
}

/// Keep this owner alive while serving; dropping it stops admission and drains accepted work.
pub struct DbWriter {
    handle: DbHandle,
    done: Option<oneshot::Receiver<()>>,
}
impl DbWriter {
    fn stop(&self) {
        self.handle.stopping.store(true, Ordering::Release);
        // Wake an idle receiver. A full queue already has work to wake it.
        let _ = self.handle.sender.try_send(Command::Stop);
    }

    /// Stop admission and wait up to five seconds for the drain and root-lock release.
    /// On timeout, accepted work continues on the thread while retaining the root lock.
    pub async fn shutdown(mut self) -> RelayResult<()> {
        self.stop();
        let done = self.done.take().ok_or(RelayError::StorageUnavailable)?;
        tokio::time::timeout(std::time::Duration::from_secs(5), done)
            .await
            .map_err(|_| RelayError::StorageUnavailable)?
            .map_err(|_| RelayError::StorageUnavailable)
    }
}
impl Drop for DbWriter {
    fn drop(&mut self) {
        self.stop();
    }
}

struct FreshPermit {
    counter: Arc<AtomicUsize>,
}
impl Drop for FreshPermit {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::AcqRel);
    }
}

struct ReplySender<T> {
    sender: oneshot::Sender<RelayResult<T>>,
    fresh: Option<FreshPermit>,
    #[cfg(test)]
    pause: Option<Pause>,
}
fn reply<T>() -> (ReplySender<T>, DbReply<T>) {
    let (sender, receiver) = oneshot::channel();
    (
        ReplySender {
            sender,
            fresh: None,
            #[cfg(test)]
            pause: None,
        },
        DbReply(receiver),
    )
}

enum ClassifyJob {
    Put {
        mailbox: Id32,
        object: Object,
        append: Capability,
        reply: std_mpsc::Sender<ClassifyOutcome>,
    },
    Hash {
        mailbox: Id32,
        hash: Id32,
        append: Capability,
        reply: std_mpsc::Sender<RelayResult<HashPresence>>,
    },
}
struct ClassifyOutcome {
    object: Object,
    append: Capability,
    class: RelayResult<PutClass>,
}
pub(crate) struct PutAdmission {
    pub object: Object,
    pub append: Capability,
    pub class: RelayResult<PutClass>,
}

fn classify_loop(root: Arc<PathBuf>, jobs: std_mpsc::Receiver<ClassifyJob>) {
    while let Ok(job) = jobs.recv() {
        match job {
            ClassifyJob::Put {
                mailbox,
                object,
                append,
                reply,
            } => {
                let class = RelayStore::classify_committed(&root, mailbox, &object, &append);
                let _ = reply.send(ClassifyOutcome {
                    object,
                    append,
                    class,
                });
            }
            ClassifyJob::Hash {
                mailbox,
                hash,
                append,
                reply,
            } => {
                let class = RelayStore::classify_committed_hash(&root, mailbox, hash, &append);
                let _ = reply.send(class);
            }
        }
    }
}
fn complete<T>(reply: ReplySender<T>, result: RelayResult<T>) {
    #[cfg(test)]
    if let Some(pause) = reply.pause {
        pause.wait();
    }
    // Losing the HTTP receiver must never cancel an accepted transaction.
    let _ = reply.sender.send(result);
}

enum Command {
    Challenge(Id32, ReplySender<Vec<u8>>),
    Create(Id32, Vec<u8>, Capability, ReplySender<CreationResult>),
    SetupControl(Id32, Vec<u8>, Capability, ReplySender<CreationResult>),
    CleanupSetup(u64, ReplySender<usize>),
    Rotate(Id32, Vec<u8>, Capability, ReplySender<u64>),
    Put(Id32, Object, Capability, ReplySender<StoredResult>),
    ClaimNonce(
        Id32,
        Id32,
        Id32,
        Vec<u8>,
        ClaimProof,
        ReplySender<(bool, Vec<u8>)>,
    ),
    Get(Id32, Id32, Capability, ReplySender<Vec<u8>>),
    Page(Id32, u64, u16, Capability, ReplySender<Page>),
    Stop,
    #[cfg(test)]
    Barrier(Pause),
    #[cfg(test)]
    Fail,
}

impl DbHandle {
    /// Open the connection and acquire the root lock on the dedicated database thread.
    /// Provisioning a fresh root remains the existing offline RelayStore::init operation.
    pub async fn open(root: PathBuf, limits: Limits) -> RelayResult<(Self, DbWriter)> {
        let root = Arc::new(root);
        let (classify_tx, classify_rx) = std_mpsc::sync_channel(CLASSIFY_QUEUE_CAPACITY);
        let (hash_tx, hash_rx) = std_mpsc::sync_channel(CLASSIFY_QUEUE_CAPACITY);
        let (sender, mut receiver) = mpsc::channel(WRITER_QUEUE_CAPACITY);
        let handle = Self {
            sender,
            stopping: Arc::new(AtomicBool::new(false)),
            root: Arc::clone(&root),
            classify: classify_tx,
            classify_hash: hash_tx,
            fresh: Arc::new(AtomicUsize::new(0)),
        };
        let classify_root = Arc::clone(&handle.root);
        std::thread::Builder::new()
            .name("relay-db-classify".into())
            .spawn(move || classify_loop(classify_root, classify_rx))
            .map_err(|_| RelayError::StorageUnavailable)?;
        let hash_root = Arc::clone(&root);
        std::thread::Builder::new()
            .name("relay-db-screen-hash".into())
            .spawn(move || classify_loop(hash_root, hash_rx))
            .map_err(|_| RelayError::StorageUnavailable)?;
        let stopping = Arc::clone(&handle.stopping);
        let (ready_tx, ready_rx) = oneshot::channel();
        let (done_tx, done_rx) = oneshot::channel();
        let owner = DbWriter {
            handle: handle.clone(),
            done: Some(done_rx),
        };
        let writer_root = Arc::clone(&root);
        std::thread::Builder::new()
            .name("relay-db-writer".into())
            .spawn(move || {
                let mut store = match RelayStore::open(writer_root.as_ref(), limits) {
                    Ok(store) => store,
                    Err(error) => {
                        let _ = ready_tx.send(Err(error));
                        return;
                    }
                };
                if ready_tx.send(Ok(())).is_err() {
                    return;
                }
                loop {
                    if stopping.load(Ordering::Acquire) {
                        receiver.close();
                    }
                    let Some(command) = receiver.blocking_recv() else {
                        break;
                    };
                    match command {
                        Command::Challenge(nonce, reply) => {
                            complete(reply, store.challenge(nonce));
                        }
                        Command::Create(mailbox, body, capability, reply) => {
                            let result = store.create(mailbox, &body, &capability);
                            complete(reply, result);
                        }
                        Command::SetupControl(mailbox, body, capability, reply) => {
                            complete(reply, store.setup_control(mailbox, &body, &capability));
                        }
                        Command::CleanupSetup(now, reply) => {
                            complete(reply, store.cleanup_setup(now));
                        }
                        Command::Rotate(mailbox, body, capability, reply) => {
                            let result = store.rotate(mailbox, &body, &capability);
                            complete(reply, result);
                        }
                        Command::Put(mailbox, object, capability, reply) => {
                            let result = store.put(mailbox, &object, &capability);
                            complete(reply, result);
                        }
                        Command::ClaimNonce(mailbox, cid, challenge, wire, proof, reply) => {
                            let result =
                                store.claim_nonce(mailbox, cid, challenge, &wire, &proof);
                            complete(reply, result);
                        }
                        Command::Get(mailbox, hash, capability, reply) => {
                            let result = store.get(mailbox, hash, &capability);
                            complete(reply, result);
                        }
                        Command::Page(mailbox, after, limit, capability, reply) => {
                            let result = store.page(mailbox, after, limit, &capability);
                            complete(reply, result);
                        }
                        Command::Stop => receiver.close(),
                        #[cfg(test)]
                        Command::Barrier(pause) => pause.wait(),
                        #[cfg(test)]
                        Command::Fail => return,
                    }
                }
                drop(store);
                let _ = done_tx.send(());
            })
            .map_err(|_| RelayError::StorageUnavailable)?;
        ready_rx
            .await
            .map_err(|_| RelayError::StorageUnavailable)??;
        Ok((handle, owner))
    }

    fn admit(&self, command: Command) -> RelayResult<()> {
        if self.stopping.load(Ordering::Acquire) {
            return Err(RelayError::StorageUnavailable);
        }
        self.sender.try_send(command).map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => RelayError::RateLimit,
            mpsc::error::TrySendError::Closed(_) => RelayError::StorageUnavailable,
        })
    }

    fn acquire_fresh(&self) -> Option<FreshPermit> {
        let mut current = self.fresh.load(Ordering::Acquire);
        loop {
            if current >= FRESH_QUEUE_LIMIT {
                return None;
            }
            match self.fresh.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Some(FreshPermit {
                        counter: Arc::clone(&self.fresh),
                    });
                }
                Err(observed) => current = observed,
            }
        }
    }

    fn admit_fresh<T>(
        &self,
        build: impl FnOnce(ReplySender<T>) -> Command,
    ) -> RelayResult<DbReply<T>> {
        let (mut sender, reply) = reply();
        sender.fresh = Some(self.acquire_fresh().ok_or(RelayError::RateLimit)?);
        self.admit(build(sender))?;
        Ok(reply)
    }

    /// Advisory snapshot on the classify thread. The caller still runs `put`.
    pub(crate) fn classify_put(
        &self,
        mailbox: Id32,
        object: Object,
        append: Capability,
    ) -> RelayResult<PutAdmission> {
        if self.stopping.load(Ordering::Acquire) {
            return Err(RelayError::StorageUnavailable);
        }
        let (reply_tx, reply_rx) = std_mpsc::channel();
        self.classify
            .try_send(ClassifyJob::Put {
                mailbox,
                object,
                append,
                reply: reply_tx,
            })
            .map_err(|error| match error {
                std_mpsc::TrySendError::Full(_) => RelayError::RateLimit,
                std_mpsc::TrySendError::Disconnected(_) => RelayError::StorageUnavailable,
            })?;
        let outcome = reply_rx
            .recv_timeout(CLASSIFY_TIMEOUT)
            .map_err(|_| RelayError::StorageUnavailable)?;
        Ok(PutAdmission {
            object: outcome.object,
            append: outcome.append,
            class: outcome.class,
        })
    }

    /// Presence only. Callers still run `put` after the body is buffered.
    pub(crate) fn classify_hash(
        &self,
        mailbox: Id32,
        hash: Id32,
        append: Capability,
    ) -> RelayResult<HashPresence> {
        if self.stopping.load(Ordering::Acquire) {
            return Err(RelayError::StorageUnavailable);
        }
        let (reply_tx, reply_rx) = std_mpsc::channel();
        self.classify_hash
            .try_send(ClassifyJob::Hash {
                mailbox,
                hash,
                append,
                reply: reply_tx,
            })
            .map_err(|error| match error {
                std_mpsc::TrySendError::Full(_) => RelayError::RateLimit,
                std_mpsc::TrySendError::Disconnected(_) => RelayError::StorageUnavailable,
            })?;
        reply_rx
            .recv_timeout(CLASSIFY_TIMEOUT)
            .map_err(|_| RelayError::StorageUnavailable)?
    }

    pub(crate) fn authenticate(
        &self,
        target: Option<(Id32, Role)>,
        capability: &Capability,
    ) -> RelayResult<()> {
        if self.stopping.load(Ordering::Acquire) {
            return Err(RelayError::StorageUnavailable);
        }
        RelayStore::authenticate_committed(&self.root, target, capability)
    }

    pub(crate) fn authenticate_nonce(
        &self,
        mailbox: Id32,
        cid: Id32,
        challenge: Id32,
        wire: &[u8],
        proof: &ClaimProof,
    ) -> RelayResult<()> {
        if self.stopping.load(Ordering::Acquire) {
            return Err(RelayError::StorageUnavailable);
        }
        RelayStore::authenticate_committed_nonce(&self.root, mailbox, cid, challenge, wire, proof)
    }

    pub fn create(
        &self,
        mailbox: Id32,
        request: Vec<u8>,
        provision: Capability,
    ) -> RelayResult<DbReply<CreationResult>> {
        self.admit_fresh(|sender| Command::Create(mailbox, request, provision, sender))
    }
    pub fn setup_control(
        &self,
        mailbox: Id32,
        request: Vec<u8>,
        provision: Capability,
    ) -> RelayResult<DbReply<CreationResult>> {
        self.admit_fresh(|sender| Command::SetupControl(mailbox, request, provision, sender))
    }
    pub fn cleanup_setup(&self, now: u64) -> RelayResult<DbReply<usize>> {
        self.admit_fresh(|sender| Command::CleanupSetup(now, sender))
    }
    pub fn challenge(&self, nonce: Id32) -> RelayResult<DbReply<Vec<u8>>> {
        // Public identity checks must not consume reserved writer progress.
        self.admit_fresh(|sender| Command::Challenge(nonce, sender))
    }
    pub fn rotate(
        &self,
        mailbox: Id32,
        request: Vec<u8>,
        admin: Capability,
    ) -> RelayResult<DbReply<u64>> {
        self.admit_fresh(|sender| Command::Rotate(mailbox, request, admin, sender))
    }
    pub fn put(
        &self,
        mailbox: Id32,
        object: Object,
        append: Capability,
    ) -> RelayResult<DbReply<StoredResult>> {
        let admission = self.classify_put(mailbox, object, append)?;
        let reserved = match admission.class {
            Ok(PutClass::Fresh) => false,
            Ok(PutClass::Duplicate(_))
            | Err(RelayError::Conflict)
            | Err(RelayError::Capability) => true,
            Err(error) => return Err(error),
        };
        let (mut sender, reply) = reply();
        if !reserved {
            sender.fresh = Some(self.acquire_fresh().ok_or(RelayError::RateLimit)?);
        }
        self.admit(Command::Put(
            mailbox,
            admission.object,
            admission.append,
            sender,
        ))?;
        Ok(reply)
    }
    pub fn claim_nonce(
        &self,
        mailbox: Id32,
        cid: Id32,
        challenge: Id32,
        wire: Vec<u8>,
        proof: ClaimProof,
    ) -> RelayResult<DbReply<(bool, Vec<u8>)>> {
        self.admit_fresh(|reply| {
            Command::ClaimNonce(mailbox, cid, challenge, wire, proof, reply)
        })
    }
    pub fn page(
        &self,
        mailbox: Id32,
        after: u64,
        limit: u16,
        read: Capability,
    ) -> RelayResult<DbReply<Page>> {
        let (sender, reply) = reply();
        self.admit(Command::Page(mailbox, after, limit, read, sender))?;
        Ok(reply)
    }
    pub fn get(
        &self,
        mailbox: Id32,
        hash: Id32,
        read: Capability,
    ) -> RelayResult<DbReply<Vec<u8>>> {
        let (sender, reply) = reply();
        self.admit(Command::Get(mailbox, hash, read, sender))?;
        Ok(reply)
    }
}

#[cfg(test)]
struct Pause {
    entered: oneshot::Sender<std::thread::ThreadId>,
    release: std::sync::mpsc::Receiver<()>,
}
#[cfg(test)]
impl Pause {
    fn wait(self) {
        let _ = self.entered.send(std::thread::current().id());
        self.release
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("test barrier release");
    }
}

#[cfg(test)]
mod tests {
    use crate as loki_relay_server;
    include!("../tests/http.rs");
    writer_private_tests!();
    snapshot_writer_tests!();
}
