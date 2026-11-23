//! Fixed diagnostic events for the native app's log file. Each one maps to our own wording;
//! no coordinator, relay or peer text, address, amount or vault name is ever logged.
// Only the native app has a log sink; other builds still type-check every event.
#![cfg_attr(not(any(test, all(target_os = "macos", feature = "apple-enclave", feature = "relay-communication"))), allow(dead_code))]

pub(super) use super::registration::Refusal;

/// Why a draft could not be funded, recognised from the host's own error text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DraftRefusal { WaitingForConfirmations, NoSingleNote, InsufficientFunds, Other }

/// Why a signing attempt ended, without any peer or coordinator text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PaymentFailure { ApprovalTimeout, Refused, ShareDeadline, Other }

// The file sink accepts only these messages, never a coordinator response, request or secret.
pub(super) enum Event {
    Registered,
    RegistrationFailed,
    CoordinatorUnavailable,
    RegistrationRefused(Refusal),
    RegistrationKeyUnavailable,
    /// A relay (frostd) sync failed. Logged once until the relay is reachable again.
    RelayUnavailable,
    RelayReachable,
    /// A lightwalletd scan failed. Logged once until a scan succeeds again.
    WalletSyncFailed,
    WalletSynced,
    DraftRefused(DraftRefusal),
    PaymentApproved,
    PaymentRefused,
    PaymentFailed(PaymentFailure),
    PaymentSigned,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    /// Logged.
    Info,
    /// Logged and shown as the launch's last error.
    Error,
    /// Logged only on a change between failing and working.
    Failing,
    Recovered,
}

impl Event {
    pub(super) fn describe(&self) -> (&'static str, Kind) {
        match self {
            Event::Registered => ("Registered with the coordinator.", Kind::Info),
            Event::RegistrationFailed => ("LokiSigner couldn’t register with the coordinator.", Kind::Error),
            Event::CoordinatorUnavailable => ("LokiSigner couldn’t reach the coordinator. Check your connection.", Kind::Error),
            Event::RegistrationRefused(reason) => (match reason {
                Refusal::ExpiredChallenge => "The coordinator refused to register this device: the pairing link expired, was already used or changed. Paste a new pairing link.",
                Refusal::GrantRequired => "The coordinator refused to register this device: it needs a valid onboarding grant. The pairing link has probably expired; paste a new one.",
                Refusal::GrantUsed => "The coordinator refused to register this device: its onboarding grant was already used.",
                Refusal::SlotTaken => "The coordinator refused to register this device: that member slot is already registered or reserved.",
                Refusal::WrongSlot => "The coordinator refused to register this device: this identity is registered to a different slot.",
                Refusal::Other => "The coordinator refused to register this device.",
            }, Kind::Error),
            Event::RegistrationKeyUnavailable => ("LokiSigner couldn’t use its device key to register.", Kind::Error),
            Event::RelayUnavailable => ("LokiSigner couldn’t sync payment messages with the relay. It will keep retrying.", Kind::Failing),
            Event::RelayReachable => ("LokiSigner reached the relay again.", Kind::Recovered),
            Event::WalletSyncFailed => ("LokiSigner couldn’t scan the chain through lightwalletd. It will keep retrying.", Kind::Failing),
            Event::WalletSynced => ("LokiSigner scanned the chain again.", Kind::Recovered),
            Event::DraftRefused(reason) => (match reason {
                DraftRefusal::WaitingForConfirmations => "Payment draft refused: the funds are waiting for confirmations.",
                DraftRefusal::NoSingleNote => "Payment draft refused: no single spendable note covers the amount and fee.",
                DraftRefusal::InsufficientFunds => "Payment draft refused: not enough spendable funds.",
                DraftRefusal::Other => "Payment draft refused.",
            }, Kind::Info),
            Event::PaymentApproved => ("Payment approved on this Mac.", Kind::Info),
            Event::PaymentRefused => ("Payment approval was refused or not completed on this Mac.", Kind::Error),
            Event::PaymentFailed(reason) => (match reason {
                PaymentFailure::ApprovalTimeout => "LokiSigner couldn’t complete the payment: approval timed out.",
                PaymentFailure::Refused => "LokiSigner couldn’t complete the payment: the approval was refused.",
                PaymentFailure::ShareDeadline => "LokiSigner couldn’t complete the payment: the signing round timed out waiting for members.",
                PaymentFailure::Other => "LokiSigner couldn’t complete the payment. Check the wallet for details.",
            }, Kind::Error),
            Event::PaymentSigned => ("LokiSigner signed a payment.", Kind::Info),
        }
    }

    /// Which repeating condition a failing or recovered event belongs to.
    pub(super) fn condition(&self) -> Option<usize> {
        match self {
            Event::RelayUnavailable | Event::RelayReachable => Some(0),
            Event::WalletSyncFailed | Event::WalletSynced => Some(1),
            _ => None,
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    fn every_event() -> Vec<Event> {
        let mut events = vec![
            Event::Registered, Event::RegistrationFailed, Event::CoordinatorUnavailable, Event::RegistrationKeyUnavailable,
            Event::RelayUnavailable, Event::RelayReachable, Event::WalletSyncFailed, Event::WalletSynced,
            Event::PaymentApproved, Event::PaymentRefused, Event::PaymentSigned,
        ];
        for reason in [Refusal::ExpiredChallenge, Refusal::GrantRequired, Refusal::GrantUsed, Refusal::SlotTaken, Refusal::WrongSlot, Refusal::Other] {
            events.push(Event::RegistrationRefused(reason));
        }
        for reason in [DraftRefusal::WaitingForConfirmations, DraftRefusal::NoSingleNote, DraftRefusal::InsufficientFunds, DraftRefusal::Other] {
            events.push(Event::DraftRefused(reason));
        }
        for reason in [PaymentFailure::ApprovalTimeout, PaymentFailure::Refused, PaymentFailure::ShareDeadline, PaymentFailure::Other] {
            events.push(Event::PaymentFailed(reason));
        }
        events
    }

    #[test]
    fn every_event_is_one_distinct_fixed_line() {
        let messages: Vec<_> = every_event().iter().map(|event| event.describe().0).collect();
        for message in &messages {
            assert!(!message.is_empty() && message.ends_with('.'), "{message}");
            assert!(!message.contains(['\n', '\r', '{', '}']), "{message}");
        }
        let distinct: std::collections::BTreeSet<_> = messages.iter().collect();
        assert_eq!(distinct.len(), messages.len(), "each event must be told apart in the log");
    }

    #[test]
    fn only_repeating_conditions_pair_failing_with_recovered() {
        for event in every_event() {
            let (_, kind) = event.describe();
            assert_eq!(event.condition().is_some(), matches!(kind, Kind::Failing | Kind::Recovered));
        }
    }
}
