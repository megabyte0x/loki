use crate::{AdmissionError, AdmissionResult, AdmissionStore, ProvisionIntent};
use loki_relay_client::{OperatorSet, RelayHttp, Secret32};
use loki_relay_protocol::types::RelayRoute;
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Instant,
};

pub struct OwnedProvisioner {
    routes: [RelayRoute; 3],
    credentials: [Secret32; 3],
    http: RelayHttp,
    next_relay: AtomicUsize,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProvisionProgress {
    pub attempted: usize,
    pub completed: usize,
}
impl OwnedProvisioner {
    pub fn new(operators: &OperatorSet, credentials: [Secret32; 3]) -> AdmissionResult<Self> {
        Self::build(operators, credentials, false)
    }
    pub fn development(
        operators: &OperatorSet,
        credentials: [Secret32; 3],
    ) -> AdmissionResult<Self> {
        Self::build(operators, credentials, true)
    }
    fn build(
        operators: &OperatorSet,
        credentials: [Secret32; 3],
        development: bool,
    ) -> AdmissionResult<Self> {
        for route in operators.relay_routes() {
            loki_relay_client::validate_endpoint(&route.endpoint, development)
                .map_err(|_| AdmissionError::Malformed)?;
        }
        Ok(Self {
            routes: operators
                .relay_routes()
                .to_vec()
                .try_into()
                .map_err(|_| AdmissionError::Malformed)?,
            credentials,
            http: RelayHttp::for_setup(operators, development)
                .map_err(|_| AdmissionError::Unavailable)?,
            next_relay: AtomicUsize::new(0),
        })
    }
    async fn attempt(
        &self,
        store: &Arc<Mutex<AdmissionStore>>,
        intent: Option<ProvisionIntent>,
        now: u64,
        started: Instant,
    ) -> AdmissionResult<Option<bool>> {
        let Some(intent) = intent else {
            return Ok(None);
        };
        let index = usize::from(
            intent
                .relay()
                .checked_sub(1)
                .ok_or(AdmissionError::Storage)?,
        );
        let mut route = self
            .routes
            .get(index)
            .ok_or(AdmissionError::Storage)?
            .clone();
        route.mailbox = *intent.mailbox();
        let authenticated = self
            .http
            .authenticate_endpoint(&route.pin, &route.endpoint)
            .await
            .is_ok();
        let success = if !authenticated {
            false
        } else if let Some(action) = intent.action {
            self.http
                .namespace_control(
                    &route,
                    &self.credentials[index],
                    intent.request(),
                    intent.expires(),
                    action,
                )
                .await
                .is_ok()
        } else {
            self.http
                .create(&route, &self.credentials[index], intent.request())
                .await
                .is_ok()
        };
        let elapsed = started.elapsed();
        // Round up so time in flight cannot eat into the whole-second retry delay.
        let finished = now
            .saturating_add(elapsed.as_secs())
            .saturating_add(u64::from(elapsed.subsec_nanos() != 0));
        let store = store.clone();
        tokio::task::spawn_blocking(move || {
            store
                .lock()
                .map_err(|_| AdmissionError::Storage)?
                .finish_provision(&intent, success, finished)?;
            Ok(Some(success))
        })
        .await
        .map_err(|_| AdmissionError::Storage)?
    }
    pub async fn drive_once(
        &self,
        store: &Arc<Mutex<AdmissionStore>>,
        now: u64,
    ) -> AdmissionResult<ProvisionProgress> {
        let started = Instant::now();
        let relay = self.next_relay.fetch_add(1, Ordering::Relaxed) % 3;
        let db = store.clone();
        let (pending, retirements) = tokio::task::spawn_blocking(move || {
            let db = db.lock().map_err(|_| AdmissionError::Storage)?;
            Ok::<_, AdmissionError>((
                db.pending_kind(now, 3, false, relay + 1)?,
                db.pending_kind(now, 3, true, (relay + 1) % 3 + 1)?,
            ))
        })
        .await
        .map_err(|_| AdmissionError::Storage)??;

        // Reserve a slot for each kind and rotate its first relay. Give spare
        // slots to relays not in the batch before doubling up on any one relay.
        let mut pending = pending.into_iter();
        let mut retirements = retirements.into_iter();
        let mut batch: Vec<_> = pending
            .next()
            .into_iter()
            .chain(retirements.next())
            .collect();
        let mut spare: Vec<_> = pending.chain(retirements).collect();
        while batch.len() < 3 && !spare.is_empty() {
            let next = spare
                .iter()
                .position(|intent| batch.iter().all(|work| work.relay() != intent.relay()))
                .unwrap_or(0);
            batch.push(spare.remove(next));
        }
        let mut batch = batch.into_iter();
        let results = tokio::join!(
            self.attempt(store, batch.next(), now, started),
            self.attempt(store, batch.next(), now, started),
            self.attempt(store, batch.next(), now, started),
        );
        let mut progress = ProvisionProgress::default();
        let mut busy = false;
        for result in [results.0, results.1, results.2] {
            match result {
                Ok(Some(success)) => {
                    progress.attempted += 1;
                    progress.completed += usize::from(success);
                }
                Ok(None) => {}
                Err(AdmissionError::StorageBusy) => busy = true,
                Err(error) => return Err(error),
            }
        }
        if busy {
            return Err(AdmissionError::StorageBusy);
        }
        Ok(progress)
    }
}
