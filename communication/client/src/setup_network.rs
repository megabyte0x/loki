use crate::retry::now_ms;
use crate::setup_store::{add_object, key_bytes};
use crate::{
    AuthenticatedSetupRecord, ClientError, ClientResult, OwnerInbox, RelayHttp, Secret32,
    SetupInboxDescriptor, SetupStore, SetupTransport,
};
use loki_relay_protocol::{
    canonical::{self, Value},
    setup::{SetupKey, SetupPhase},
    types::{Id32, Object, RelayRoute},
};
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroizing;
const ACK_DOMAIN: &[u8] = b"Loki_Setup_Received_v1\0";
const PENDING_ROOT_LIMIT: u64 = 64;
const PENDING_ROOT_TTL_MS: u64 = 10 * 60 * 1000;
pub struct SetupRoutes {
    pub own: Vec<OwnerInbox>,
    pub peers: Vec<SetupInboxDescriptor>,
}
#[derive(Default, Debug, Eq, PartialEq)]
pub struct SetupProgress {
    pub stored_groups: usize,
    pub received_groups: usize,
    pub incoming_records: usize,
    pub retryable_routes: usize,
}
fn fields(v: &Value, n: usize) -> ClientResult<&[Value]> {
    match v {
        Value::Array(a) if a.len() == n => Ok(a),
        _ => Err(ClientError::Config),
    }
}
fn bytes(v: &Value) -> ClientResult<&[u8]> {
    match v {
        Value::Bytes(b) => Ok(b),
        _ => Err(ClientError::Config),
    }
}
fn number(v: &Value) -> ClientResult<u64> {
    match v {
        Value::Integer(n) => u64::try_from(*n).map_err(|_| ClientError::Config),
        _ => Err(ClientError::Config),
    }
}
fn decode_key(ceremony: Id32, raw: &[u8]) -> ClientResult<SetupKey> {
    let v = canonical::decode(raw, 128)?;
    let f = fields(&v, 4)?;
    Ok(SetupKey {
        ceremony,
        phase: SetupPhase::try_from(number(&f[0])?)?,
        author: u16::try_from(number(&f[1])?).map_err(|_| ClientError::Identity)?,
        recipient: u16::try_from(number(&f[2])?).map_err(|_| ClientError::Identity)?,
        revision: number(&f[3])?,
    })
}
pub(crate) struct VerifiedAck {
    pub key: Vec<u8>,
    pub digest: Id32,
    pub package: Vec<u8>,
}
impl SetupTransport<'_> {
    pub(crate) fn prepare_ack(
        &self,
        record: &AuthenticatedSetupRecord,
    ) -> ClientResult<Option<(u16, Object)>> {
        let key = &record.body().key;
        if key.author == self.identity.public().id {
            return Ok(None);
        }
        let value = Value::Array(vec![
            Value::Integer(1.into()),
            Value::Bytes(crate::setup::policy_bytes(self.context().policy())?),
            Value::Bytes(key_bytes(key)?),
            Value::Bytes(record.digest().to_vec()),
            Value::Integer(self.identity.public().id.into()),
        ]);
        let package = crate::setup::signed(self.identity, ACK_DOMAIN, canonical::encode(&value)?)?;
        let frame = canonical::encode(&Value::Array(vec![
            Value::Integer(4.into()),
            Value::Bytes(package),
        ]))?;
        Ok(Some((
            key.author,
            crate::seal_record(&self.seal_context(key.author)?, &frame)?,
        )))
    }
    pub(crate) fn open_ack(&self, object: &Object) -> ClientResult<Option<VerifiedAck>> {
        let raw = Zeroizing::new(crate::open_record(
            &self.seal_context(self.identity.public().id)?,
            self.identity,
            &object.wire,
        )?);
        let value = crate::setup::PrivateValue(canonical::decode(&raw, 65536)?);
        let Value::Array(a) = &value.0 else {
            return Err(ClientError::Config);
        };
        if a.first().map(number).transpose()? != Some(4) {
            return Ok(None);
        }
        let f = fields(&value.0, 2)?;
        Ok(Some(self.verify_ack_package(bytes(&f[1])?)?))
    }
    fn verify_ack_package(&self, package: &[u8]) -> ClientResult<VerifiedAck> {
        let outer = canonical::decode(package, 4096)?;
        let p = fields(&outer, 2)?;
        let body = canonical::decode(bytes(&p[0])?, 4096)?;
        let b = fields(&body, 5)?;
        let author = u16::try_from(number(&b[4])?).map_err(|_| ClientError::Identity)?;
        let verified = crate::setup::verify_package(package, 4096, ACK_DOMAIN, self.peer(author)?)?;
        if verified != bytes(&p[0])?
            || number(&b[0])? != 1
            || bytes(&b[1])? != crate::setup::policy_bytes(self.context().policy())?
        {
            return Err(ClientError::Identity);
        }
        let key = decode_key(self.context().policy().ceremony, bytes(&b[2])?)?;
        if key.author != self.identity.public().id
            || key.recipient != author
            || author == key.author
        {
            return Err(ClientError::Identity);
        }
        let digest = bytes(&b[3])?
            .try_into()
            .map_err(|_| ClientError::Identity)?;
        Ok(VerifiedAck {
            key: key_bytes(&key)?,
            digest,
            package: package.to_vec(),
        })
    }
    fn check_routes(&self, routes: &SetupRoutes) -> ClientResult<()> {
        if routes.own.len() != 3 {
            return Err(ClientError::Config);
        }
        let mut seen = BTreeSet::new();
        for (own, pin) in routes.own.iter().zip(self.operators.relay_routes()) {
            if own.route.pin != pin.pin
                || own.route.endpoint != pin.endpoint
                || own.route.mailbox == [0; 32]
                || own.route.append_revision != 1
                || *own.read.as_bytes() == [0; 32]
                || *own.append.as_bytes() == [0; 32]
                || *own.admin.as_bytes() == [0; 32]
                || !seen.insert(own.route.mailbox)
            {
                return Err(ClientError::Config);
            }
        }
        seen.clear();
        for peer in &routes.peers {
            if peer.policy() != self.context().policy()
                || self.peer(peer.owner())? != peer.owner_identity()
                || peer.owner() == self.identity.public().id
                || !seen.insert(peer.owner_identity().signing)
            {
                return Err(ClientError::Identity);
            }
        }
        Ok(())
    }
    fn append_route<'a>(
        &self,
        routes: &'a SetupRoutes,
        recipient: u16,
        index: usize,
    ) -> Option<(&'a RelayRoute, &'a Secret32)> {
        if recipient == self.identity.public().id {
            routes.own.get(index).map(|r| (&r.route, &r.append))
        } else {
            routes
                .peers
                .iter()
                .find(|p| p.owner() == recipient)
                .and_then(|p| p.relays().get(index))
                .map(|r| (&r.route, &r.append))
        }
    }
    pub async fn drive_once(
        &self,
        store: &mut SetupStore,
        routes: &SetupRoutes,
    ) -> ClientResult<SetupProgress> {
        let net = SetupNet::new(self.operators, self.development)?;
        self.drive_once_with(store, routes, &net).await
    }
    /// One drive over all three relays at once, reusing `net`'s connections and
    /// endpoint checks. Each network phase has a `request_seconds` deadline: a slow or
    /// failing relay defers only its own route.
    pub async fn drive_once_with(
        &self,
        store: &mut SetupStore,
        routes: &SetupRoutes,
        net: &SetupNet,
    ) -> ClientResult<SetupProgress> {
        store.check_transport(self)?;
        store.active()?;
        self.check_routes(routes)?;
        let mut retries = 0;
        self.drive_bounded(store, routes, net, &mut retries).await?;
        let mut progress = store.progress(self, routes)?;
        progress.retryable_routes = retries;
        Ok(progress)
    }
    async fn drive_bounded(
        &self,
        store: &mut SetupStore,
        routes: &SetupRoutes,
        net: &SetupNet,
        retries: &mut usize,
    ) -> ClientResult<()> {
        store.reconcile_deferred(self)?;
        // Plan: everything that needs the store, before any request.
        // Every network phase gets its own deadline: a relay that hangs through the
        // first phase is dropped from the later ones and must not use up their time.
        let limit = std::time::Duration::from_secs(self.operators.limits().request_seconds);
        let phase_deadline = || tokio::time::Instant::now() + limit;
        let mut plans = Vec::new();
        for (index, own) in routes.own.iter().enumerate() {
            let pin = self.operators.relay_routes()[index].pin.key;
            if !store.route_due(&pin)? {
                *retries += 1;
                continue;
            }
            let mut uploads = Vec::new();
            for (key, recipient, object, ack) in store.uploads(&pin, 64)? {
                if let Some((route, cap)) = self.append_route(routes, recipient, index) {
                    uploads.push(Upload {
                        key,
                        object,
                        ack,
                        route,
                        cap,
                    });
                }
            }
            plans.push(RelayPlan {
                pin,
                own,
                after: store.cursor(&own.route)?,
                uploads,
            });
        }
        // Network, first half: endpoint check, uploads and the inbox page, all relays at once.
        let deadline = phase_deadline();
        let first = join_all(
            plans
                .iter()
                .map(|plan| self.upload_and_list(net, plan, deadline))
                .collect(),
        )
        .await;
        // Objects already held locally are not downloaded again.
        let mut held = BTreeMap::new();
        for listed in first.iter().flatten() {
            for entry in listed.page.entries() {
                if !held.contains_key(entry.hash()) {
                    if let Some(object) = store.object(entry.hash())? {
                        held.insert(*entry.hash(), object);
                    }
                }
            }
        }
        // Network, second half: each missing object from the first relay that lists it,
        // then (only after a failure) from every other relay that lists it.
        let mut owner = BTreeMap::new();
        for (index, listed) in first.iter().enumerate() {
            if let Ok(listed) = listed {
                for entry in listed.page.entries() {
                    if !held.contains_key(entry.hash()) {
                        owner.entry(*entry.hash()).or_insert(index);
                    }
                }
            }
        }
        let deadline = phase_deadline();
        let fetched = join_all(
            plans
                .iter()
                .zip(&first)
                .enumerate()
                .map(|(index, (plan, listed))| {
                    let wanted: Vec<_> = match listed {
                        Ok(listed) => listed
                            .page
                            .entries()
                            .iter()
                            .filter(|e| owner.get(e.hash()) == Some(&index))
                            .map(|e| *e.hash())
                            .collect(),
                        Err(_) => Vec::new(),
                    };
                    async move {
                        tokio::time::timeout_at(deadline, fetch_objects(net, plan.own, wanted))
                            .await
                            .unwrap_or_default()
                    }
                })
                .collect(),
        )
        .await;
        for objects in fetched {
            held.extend(objects);
        }
        let deadline = phase_deadline();
        let retry = join_all(
            plans
                .iter()
                .zip(&first)
                .map(|(plan, listed)| {
                    let wanted: Vec<_> = match listed {
                        Ok(listed) => listed
                            .page
                            .entries()
                            .iter()
                            .filter(|e| !held.contains_key(e.hash()))
                            .map(|e| *e.hash())
                            .collect(),
                        Err(_) => Vec::new(),
                    };
                    async move {
                        tokio::time::timeout_at(deadline, fetch_objects(net, plan.own, wanted))
                            .await
                            .unwrap_or_default()
                    }
                })
                .collect(),
        )
        .await;
        for objects in retry {
            held.extend(objects);
        }
        // Only receipt-verified listings schedule downloads. Setup senders publish each
        // chunk as its own entry; an unsigned manifest never expands the network work.
        // Apply, in relay order: receipts, then the page exactly as a sequential drive would.
        for (plan, listed) in plans.iter().zip(first) {
            let listed = match listed {
                Ok(listed) => listed,
                Err(failure) => {
                    for (upload, receipt) in failure.receipts {
                        let upload = &plan.uploads[upload];
                        store.save_receipt(
                            &upload.key,
                            &plan.pin,
                            &upload.object.hash,
                            receipt.bytes(),
                            upload.ack,
                        )?;
                    }
                    net.forget(&plan.pin);
                    *retries += 1;
                    store.defer_route(self, &plan.pin)?;
                    continue;
                }
            };
            for (upload, receipt) in &listed.receipts {
                let upload = &plan.uploads[*upload];
                store.save_receipt(
                    &upload.key,
                    &plan.pin,
                    &upload.object.hash,
                    receipt.bytes(),
                    upload.ack,
                )?;
            }
            let own = plan.own;
            let page = &listed.page;
            let mut cached = BTreeMap::new();
            let mut acknowledgements = Vec::new();
            let mut rejected = Vec::new();
            let mut pending = Vec::new();
            let mut incomplete = false;
            for entry in page.entries() {
                let object = match held.get(entry.hash()) {
                    Some(o) if o.wire.len() as u64 == entry.wire_length() => o.clone(),
                    _ => {
                        *retries += 1;
                        incomplete = true;
                        break;
                    }
                };
                cached.insert(object.hash, object.clone());
                match self.open_ack(&object) {
                    Ok(Some(ack)) => {
                        acknowledgements.push(ack);
                        continue;
                    }
                    Ok(None) => {}
                    Err(_) => {
                        rejected.push(object.hash);
                        continue;
                    }
                }
                match self.consume_root(store, &object, &held)? {
                    RootDisposition::Settled => {}
                    RootDisposition::Pending => pending.push(object.hash),
                    RootDisposition::Rejected => rejected.push(object.hash),
                }
            }
            if incomplete {
                store.defer_route(self, &own.route.pin.key)?;
            } else {
                store.capture_page(
                    &own.route,
                    plan.after,
                    page.next(),
                    &cached,
                    &acknowledgements,
                    &rejected,
                    &pending,
                )?;
                store.connection.execute(
                    "DELETE FROM retries WHERE pin=?1",
                    [own.route.pin.key.as_slice()],
                )?;
            }
        }
        // A later listing (including another relay's) can complete a saved root.
        for object in store.pending_roots()? {
            let disposition = self.consume_root(store, &object, &BTreeMap::new())?;
            if !matches!(disposition, RootDisposition::Pending) {
                let tx = store.connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
                if matches!(disposition, RootDisposition::Rejected) {
                    tx.execute("INSERT OR IGNORE INTO rejected VALUES(?1)", [object.hash])?;
                }
                tx.execute("DELETE FROM pending_roots WHERE hash=?1", [object.hash])?;
                tx.commit()?;
            }
        }
        Ok(())
    }

    fn consume_root(
        &self,
        store: &mut SetupStore,
        root: &Object,
        held: &BTreeMap<Id32, Object>,
    ) -> ClientResult<RootDisposition> {
        let requirements = match self.inspect(root) {
            Ok(requirements) => requirements,
            Err(ClientError::MissingObjects(hashes)) if hashes.is_empty() => {
                return Ok(RootDisposition::Settled); // Standalone chunk entry.
            }
            Err(_) => return Ok(RootDisposition::Rejected),
        };
        let mut chunks = BTreeMap::new();
        for (hash, _) in requirements {
            let object = if let Some(object) = held.get(&hash) {
                object.clone()
            } else if let Some(object) = store.object(&hash)? {
                object
            } else {
                return Ok(RootDisposition::Pending);
            };
            chunks.insert(hash, object);
        }
        match store.commit_incoming(self, root, &chunks) {
            Ok(_) | Err(ClientError::SetupAgreementPending) => Ok(RootDisposition::Settled),
            Err(error @ (ClientError::Storage | ClientError::Capacity | ClientError::Conflict)) => Err(error),
            Err(_) => Ok(RootDisposition::Rejected),
        }
    }
    async fn upload_and_list(
        &self,
        net: &SetupNet,
        plan: &RelayPlan<'_>,
        deadline: tokio::time::Instant,
    ) -> Result<Listed, RelayFailure> {
        // The deadline applies to each request here, so receipts from uploads that
        // finished before it expires are returned and saved rather than dropped.
        let own = plan.own;
        if !matches!(
            tokio::time::timeout_at(deadline, net.authenticate(&own.route.pin, &own.route.endpoint))
                .await,
            Ok(Ok(_))
        ) {
            return Err(RelayFailure {
                receipts: Vec::new(),
            });
        }
        let mut receipts = Vec::new();
        for (chunk, uploads) in plan.uploads.chunks(IN_FLIGHT).enumerate() {
            let Ok(results) = tokio::time::timeout_at(
                deadline,
                join_all(
                    uploads
                        .iter()
                        .map(|upload| net.http.put(upload.route, upload.cap, &upload.object))
                        .collect(),
                ),
            )
            .await
            else {
                return Err(RelayFailure { receipts });
            };
            let mut failed = false;
            for (offset, result) in results.into_iter().enumerate() {
                match result {
                    Ok(receipt) => receipts.push((chunk * IN_FLIGHT + offset, receipt)),
                    Err(_) => failed = true,
                }
            }
            if failed {
                return Err(RelayFailure { receipts });
            }
        }
        match tokio::time::timeout_at(
            deadline,
            net.http.entries(&own.route, &own.read, plan.after, Some(32)),
        )
        .await
        {
            Ok(Ok(page)) => Ok(Listed { receipts, page }),
            _ => Err(RelayFailure { receipts }),
        }
    }
}
/// At most this many requests are in flight to one relay from one drive.
const IN_FLIGHT: usize = 4;
/// A relay endpoint check is reused for this long; any failure on that relay clears it.
const ENDPOINT_TTL: std::time::Duration = std::time::Duration::from_secs(600);
/// Connections and endpoint checks shared by consecutive setup drives.
pub struct SetupNet {
    http: RelayHttp,
    verified: std::sync::Mutex<BTreeMap<(Id32, String), std::time::Instant>>,
}
impl SetupNet {
    pub fn new(operators: &crate::OperatorSet, development: bool) -> ClientResult<Self> {
        Ok(Self {
            http: RelayHttp::for_setup(operators, development)?,
            verified: std::sync::Mutex::new(BTreeMap::new()),
        })
    }
    /// `authenticate_endpoint` is a reachability and pin check that does not
    /// authenticate later requests (every receipt, page and object is verified on
    /// its own), so a recent success can be reused.
    async fn authenticate(
        &self,
        pin: &loki_relay_protocol::types::RelayPin,
        endpoint: &str,
    ) -> ClientResult<()> {
        crate::validate_endpoint(endpoint, self.http.development())?;
        let key = (pin.key, endpoint.to_owned());
        if let Some(at) = self
            .verified
            .lock()
            .map_err(|_| ClientError::Storage)?
            .get(&key)
        {
            if at.elapsed() < ENDPOINT_TTL {
                return Ok(());
            }
        }
        self.http.authenticate_endpoint(pin, endpoint).await?;
        self.verified
            .lock()
            .map_err(|_| ClientError::Storage)?
            .insert(key, std::time::Instant::now());
        Ok(())
    }
    fn forget(&self, pin: &Id32) {
        if let Ok(mut verified) = self.verified.lock() {
            verified.retain(|(key, _), _| key != pin);
        }
    }
}
struct Upload<'a> {
    key: Vec<u8>,
    object: Object,
    ack: bool,
    route: &'a RelayRoute,
    cap: &'a Secret32,
}
struct RelayPlan<'a> {
    pin: Id32,
    own: &'a OwnerInbox,
    after: u64,
    uploads: Vec<Upload<'a>>,
}
struct Listed {
    receipts: Vec<(usize, crate::VerifiedReceipt)>,
    page: crate::VerifiedPage,
}
struct RelayFailure {
    receipts: Vec<(usize, crate::VerifiedReceipt)>,
}
enum RootDisposition {
    Settled,
    Pending,
    Rejected,
}
async fn fetch_objects(net: &SetupNet, own: &OwnerInbox, wanted: Vec<Id32>) -> Vec<(Id32, Object)> {
    let mut out = Vec::new();
    for hashes in wanted.chunks(IN_FLIGHT) {
        let results = join_all(
            hashes
                .iter()
                .map(|hash| net.http.get(&own.route, &own.read, hash))
                .collect(),
        )
        .await;
        for (hash, result) in hashes.iter().zip(results) {
            if let Ok(object) = result {
                out.push((*hash, object));
            }
        }
    }
    out
}
/// Poll every future to completion on the current task; output order matches input.
pub async fn join_all<F: std::future::Future>(futures: Vec<F>) -> Vec<F::Output> {
    let mut pending: Vec<_> = futures.into_iter().map(|f| Some(Box::pin(f))).collect();
    let mut output: Vec<Option<F::Output>> = pending.iter().map(|_| None).collect();
    std::future::poll_fn(|cx| {
        let mut done = true;
        for (slot, result) in pending.iter_mut().zip(output.iter_mut()) {
            if let Some(future) = slot {
                match future.as_mut().poll(cx) {
                    std::task::Poll::Ready(value) => {
                        *result = Some(value);
                        *slot = None;
                    }
                    std::task::Poll::Pending => done = false,
                }
            }
        }
        if done {
            std::task::Poll::Ready(())
        } else {
            std::task::Poll::Pending
        }
    })
    .await;
    output.into_iter().flatten().collect()
}
impl SetupStore {
    /// Whether a drive now would upload anything: a saved record or acknowledgement
    /// not yet stored on a relay whose retry time has come.
    pub fn has_due_uploads(&self, t: &SetupTransport<'_>) -> ClientResult<bool> {
        for route in t.operators.relay_routes() {
            if self.route_due(&route.pin.key)? && !self.uploads(&route.pin.key, 1)?.is_empty() {
                return Ok(true);
            }
        }
        Ok(false)
    }
    fn object(&self, hash: &Id32) -> ClientResult<Option<Object>> {
        Ok(self
            .connection
            .query_row(
                "SELECT wire FROM objects WHERE hash=?1",
                [hash.as_slice()],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .optional()?
            .map(|wire| Object { hash: *hash, wire }))
    }
    fn route_due(&self, pin: &Id32) -> ClientResult<bool> {
        let next: Option<u64> = self
            .connection
            .query_row(
                "SELECT next_ms FROM retries WHERE pin=?1",
                [pin.as_slice()],
                |r| r.get(0),
            )
            .optional()?;
        let now = now_ms()?;
        Ok(next.is_none_or(|n| n <= now))
    }
    fn defer_route(&mut self, t: &SetupTransport<'_>, pin: &Id32) -> ClientResult<()> {
        let prior: Option<u64> = self
            .connection
            .query_row(
                "SELECT attempts FROM retries WHERE pin=?1",
                [pin.as_slice()],
                |r| r.get(0),
            )
            .optional()?;
        let attempts = prior.unwrap_or(0).saturating_add(1).min(1000000);
        let policy = t.operators.limits();
        let floor = policy.retry_min_seconds * 1000;
        let cap = (floor.saturating_mul(1u64 << attempts.saturating_sub(1).min(16)))
            .min(policy.retry_max_seconds * 1000);
        let width = cap - floor + 1;
        let cutoff = u64::MAX - (u64::MAX % width);
        let mut delay = None;
        for _ in 0..16 {
            let mut raw = [0u8; 8];
            getrandom::fill(&mut raw).map_err(|_| ClientError::Crypto)?;
            let draw = u64::from_le_bytes(raw);
            if draw < cutoff {
                delay = Some(floor + draw % width);
                break;
            }
        }
        let next = now_ms()?
            .checked_add(delay.ok_or(ClientError::Crypto)?)
            .filter(|n| *n <= i64::MAX as u64)
            .ok_or(ClientError::Capacity)?;
        self.connection.execute("INSERT INTO retries VALUES(?1,?2,?3) ON CONFLICT(pin) DO UPDATE SET attempts=excluded.attempts,next_ms=excluded.next_ms",params![pin.as_slice(),attempts,next])?;
        Ok(())
    }
    fn uploads(&self, pin: &Id32, limit: usize) -> ClientResult<Vec<(Vec<u8>, u16, Object, bool)>> {
        let mut stmt=self.connection.prepare("SELECT o.key,o.recipient,x.hash,x.wire,0 FROM outgoing o JOIN required r ON r.key=o.key JOIN objects x ON x.hash=r.hash WHERE NOT EXISTS(SELECT 1 FROM stored s WHERE s.key=o.key AND s.pin=?1 AND s.hash=x.hash) ORDER BY o.key,r.ordinal LIMIT ?2")?;
        let rows = stmt.query_map(params![pin.as_slice(), limit as i64], |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, u16>(1)?,
                r.get::<_, Vec<u8>>(2)?,
                r.get::<_, Vec<u8>>(3)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (key, recipient, hash, wire) = row?;
            out.push((
                key,
                recipient,
                Object {
                    hash: hash.try_into().map_err(|_| ClientError::Storage)?,
                    wire,
                },
                false,
            ));
        }
        let mut stmt=self.connection.prepare("SELECT a.key,a.recipient,x.hash,x.wire FROM acknowledgements a JOIN objects x ON x.hash=a.hash WHERE NOT EXISTS(SELECT 1 FROM ack_stored s WHERE s.hash=a.hash AND s.pin=?1) ORDER BY a.key LIMIT ?2")?;
        let rows = stmt.query_map(
            params![pin.as_slice(), limit.saturating_sub(out.len()) as i64],
            |r| {
                Ok((
                    r.get::<_, Vec<u8>>(0)?,
                    r.get::<_, u16>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                    r.get::<_, Vec<u8>>(3)?,
                ))
            },
        )?;
        for row in rows {
            let (key, recipient, hash, wire) = row?;
            out.push((
                key,
                recipient,
                Object {
                    hash: hash.try_into().map_err(|_| ClientError::Storage)?,
                    wire,
                },
                true,
            ));
        }
        Ok(out)
    }
    fn save_receipt(
        &mut self,
        key: &[u8],
        pin: &Id32,
        hash: &Id32,
        receipt: &[u8],
        ack: bool,
    ) -> ClientResult<()> {
        if ack {
            self.connection.execute(
                "INSERT OR IGNORE INTO ack_stored VALUES(?1,?2,?3)",
                params![hash.as_slice(), pin.as_slice(), receipt],
            )?;
        } else {
            self.connection.execute(
                "INSERT OR IGNORE INTO stored VALUES(?1,?2,?3,?4)",
                params![key, pin.as_slice(), hash.as_slice(), receipt],
            )?;
        }
        Ok(())
    }
    fn cursor(&self, route: &RelayRoute) -> ClientResult<u64> {
        let row: Option<(Vec<u8>, u64)> = self
            .connection
            .query_row(
                "SELECT mailbox,sequence FROM cursors WHERE pin=?1",
                [route.pin.key.as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        match row {
            None => Ok(0),
            Some((mailbox, seq)) if mailbox == route.mailbox => Ok(seq),
            _ => Err(ClientError::Identity),
        }
    }
    fn capture_page(
        &mut self,
        route: &RelayRoute,
        after: u64,
        next: u64,
        objects: &BTreeMap<Id32, Object>,
        acks: &[VerifiedAck],
        rejected: &[Id32],
        pending: &[Id32],
    ) -> ClientResult<()> {
        self.active()?;
        if self.cursor(route)? != after || next < after || next > i64::MAX as u64 {
            return Err(ClientError::Cursor);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        for o in objects.values() {
            add_object(&tx, o)?;
        }
        for ack in acks {
            let digest: Option<Vec<u8>> = tx
                .query_row(
                    "SELECT digest FROM outgoing WHERE key=?1",
                    [&ack.key],
                    |r| r.get(0),
                )
                .optional()?;
            if digest.as_deref() == Some(ack.digest.as_slice()) {
                tx.execute(
                    "INSERT OR IGNORE INTO received VALUES(?1,?2,?3)",
                    params![&ack.key, ack.digest.as_slice(), &ack.package],
                )?;
            }
        }
        for hash in rejected {
            tx.execute(
                "INSERT OR IGNORE INTO rejected VALUES(?1)",
                [hash.as_slice()],
            )?;
        }
        let now = now_ms()?;
        tx.execute("DELETE FROM pending_roots WHERE expires_ms<=?1", [now])?;
        let mut advance = true;
        for hash in pending {
            let inserted = tx.execute(
                "INSERT OR IGNORE INTO pending_roots SELECT ?1,?2 WHERE (SELECT count(*) FROM pending_roots)<?3",
                params![hash, now + PENDING_ROOT_TTL_MS, PENDING_ROOT_LIMIT],
            )?;
            if inserted == 0 && !tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM pending_roots WHERE hash=?1)",
                [hash],
                |row| row.get::<_, bool>(0),
            )? {
                advance = false;
            }
        }
        if advance {
            tx.execute("INSERT INTO cursors VALUES(?1,?2,?3) ON CONFLICT(pin) DO UPDATE SET sequence=excluded.sequence",params![route.pin.key.as_slice(),route.mailbox.as_slice(),next])?;
        }
        tx.commit()?;
        Ok(())
    }
    fn pending_roots(&self) -> ClientResult<Vec<Object>> {
        let mut stmt = self.connection.prepare(
            "SELECT o.hash,o.wire FROM pending_roots p JOIN objects o ON o.hash=p.hash WHERE p.expires_ms>?1 ORDER BY p.rowid LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![now_ms()?, PENDING_ROOT_LIMIT], |r| {
            let hash: Vec<u8> = r.get(0)?;
            Ok(Object { hash: hash.try_into().map_err(|_| rusqlite::Error::InvalidQuery)?, wire: r.get(1)? })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }
    pub fn progress(
        &self,
        t: &SetupTransport<'_>,
        routes: &SetupRoutes,
    ) -> ClientResult<SetupProgress> {
        self.progress_selected(t, routes, None)
    }
    pub fn progress_for(
        &self,
        t: &SetupTransport<'_>,
        routes: &SetupRoutes,
        key: &SetupKey,
    ) -> ClientResult<SetupProgress> {
        if key.ceremony != t.context().policy().ceremony
            || key.author != t.identity.public().id
            || key.recipient != key.author
            || key.revision == 0
        {
            return Err(ClientError::Identity);
        }
        self.progress_selected(t, routes, Some(key))
    }
    fn progress_selected(
        &self,
        t: &SetupTransport<'_>,
        routes: &SetupRoutes,
        selected: Option<&SetupKey>,
    ) -> ClientResult<SetupProgress> {
        self.check_transport(t)?;
        self.active()?;
        t.check_routes(routes)?;
        let mut groups = BTreeMap::<(u8, u16, u64), Vec<(Vec<u8>, Vec<u8>, u16)>>::new();
        let mut stmt = self
            .connection
            .prepare("SELECT key,digest,recipient FROM outgoing ORDER BY key")?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, u16>(2)?,
            ))
        })?;
        for row in rows {
            let (key, digest, recipient) = row?;
            let k = decode_key(t.context().policy().ceremony, &key)?;
            groups
                .entry((k.phase as u8, k.author, k.revision))
                .or_default()
                .push((key, digest, recipient));
        }
        if let Some(key) = selected {
            groups.retain(|(phase, author, revision), _| {
                *phase == key.phase as u8 && *author == key.author && *revision == key.revision
            });
        }
        let mut progress = SetupProgress::default();
        for ((phase, author, revision), copies) in &groups {
            let required: BTreeSet<u16> = if *phase == SetupPhase::Join as u8 {
                [1, *author].into_iter().collect()
            } else {
                (1..=t.context().policy().member_count).collect()
            };
            if *author != t.identity.public().id
                || copies.iter().map(|(_, _, r)| *r).collect::<BTreeSet<_>>() != required
                || copies.len() != required.len()
            {
                return Err(ClientError::Storage);
            }
            let mut pins: BTreeSet<_> = t
                .operators
                .relay_routes()
                .iter()
                .map(|r| r.pin.key)
                .collect();
            let mut received = true;
            for (key, digest, recipient) in copies {
                let mut present = BTreeSet::new();
                for (index, operator) in t.operators.relay_routes().iter().enumerate() {
                    if !pins.contains(&operator.pin.key) {
                        continue;
                    }
                    let Some((route, _)) = t.append_route(routes, *recipient, index) else {
                        continue;
                    };
                    let mut objects=self.connection.prepare("SELECT r.hash,x.wire,s.receipt FROM required r JOIN objects x ON x.hash=r.hash LEFT JOIN stored s ON s.key=r.key AND s.hash=r.hash AND s.pin=?2 WHERE r.key=?1 ORDER BY r.ordinal")?;
                    let rows =
                        objects.query_map(params![key, operator.pin.key.as_slice()], |r| {
                            Ok((
                                r.get::<_, Vec<u8>>(0)?,
                                r.get::<_, Vec<u8>>(1)?,
                                r.get::<_, Option<Vec<u8>>>(2)?,
                            ))
                        })?;
                    let mut complete = true;
                    let mut count = 0;
                    for row in rows {
                        let (hash, wire, receipt) = row?;
                        count += 1;
                        let hash: Id32 = hash.try_into().map_err(|_| ClientError::Storage)?;
                        use sha2::Digest;
                        if <Id32>::from(sha2::Sha256::digest(&wire)) != hash {
                            return Err(ClientError::Storage);
                        }
                        if let Some(receipt) = receipt {
                            crate::http::verify_saved_receipt(
                                route,
                                &receipt,
                                hash,
                                wire.len() as u64,
                            )?;
                        } else {
                            complete = false;
                        }
                    }
                    if count == 0 {
                        return Err(ClientError::Storage);
                    }
                    if complete {
                        present.insert(operator.pin.key);
                    }
                }
                pins = present;
                let confirmed = if *recipient == t.identity.public().id {
                    let k = decode_key(t.context().policy().ceremony, key)?;
                    self.receive(t, &k)?.is_some_and(|record| {
                        record.digest().as_slice() == digest
                            && record.body().key.phase as u8 == *phase
                            && record.body().key.revision == *revision
                    })
                } else {
                    let package: Option<Vec<u8>> = self
                        .connection
                        .query_row(
                            "SELECT package FROM received WHERE key=?1 AND digest=?2",
                            params![key, digest],
                            |r| r.get(0),
                        )
                        .optional()?;
                    if let Some(package) = package {
                        let ack = t.verify_ack_package(&package)?;
                        if ack.key != *key || ack.digest.as_slice() != digest {
                            return Err(ClientError::Receipt);
                        }
                        true
                    } else {
                        false
                    }
                };
                received &= confirmed;
            }
            if pins.len() >= 2 {
                progress.stored_groups += 1;
            }
            if received {
                progress.received_groups += 1;
            }
        }
        progress.incoming_records =
            self.connection
                .query_row("SELECT count(*) FROM incoming", [], |r| r.get(0))?;
        Ok(progress)
    }
}
