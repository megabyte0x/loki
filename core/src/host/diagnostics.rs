#![cfg_attr(not(any(test, all(target_os = "macos", feature = "apple-enclave", feature = "relay-communication"))), allow(dead_code))]

pub(super) use super::registration::Refusal;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DraftRefusal { WaitingForConfirmations, NoSingleNote, InsufficientFunds, Other }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PairingRefusal {
    RateLimited, SlotsFull,
    SlotHeld,
    SlotRegistered,
    Unreachable, Other,
}

impl PairingRefusal {
    pub(crate) fn native_code(self) -> &'static str {
        match self {
            Self::RateLimited => "renewal-rate-limited",
            Self::SlotsFull => "renewal-slots-full",
            Self::SlotHeld => "renewal-slot-held",
            Self::SlotRegistered => "renewal-slot-registered",
            Self::Unreachable => "renewal-unreachable",
            Self::Other => "renewal-refused",
        }
    }

    pub(crate) fn message(self) -> &'static str {
        match self {
            Self::RateLimited => "The coordinator is limiting new pairings right now. Try again later.",
            Self::SlotsFull => "The coordinator is full or has too many pairings waiting right now. Try again in a few minutes, or ask whoever runs it.",
            Self::SlotHeld => "The coordinator is holding this slot right now. Wait two minutes for the hold to expire, then try again.",
            Self::SlotRegistered => "Another member registered this coordinator slot. Remove this profile and pair again with the coordinator address.",
            Self::Unreachable => "LokiSigner couldn’t reach the coordinator. Check the address and your connection, then try again.",
            Self::Other => "The coordinator didn’t give this Mac a pairing link. Try again, or ask whoever runs it.",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PaymentFailure { ApprovalTimeout, Refused, ShareDeadline, Other }

pub(super) enum Event {
    Registered,
    RegistrationFailed,
    CoordinatorUnavailable,
    RegistrationRefused(Refusal),
    RegistrationKeyUnavailable,
    RelayUnavailable,
    RelayReachable,
    WalletSyncFailed,
    WalletSynced,
    DraftRefused(DraftRefusal),
    PaymentApproved,
    PaymentRefused,
    PaymentFailed(PaymentFailure),
    PaymentSigned,
    WitnessChangeNoticed,
    WitnessChangeKept,
    WitnessChangeTrusted,
    PairingRequested,
    PairingRefused(PairingRefusal),
    ChallengeRenewed,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    Info,
    Error,
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
                Refusal::ExpiredClaim => "The coordinator refused this pairing before this Mac signed: the reservation expired or changed.",
                Refusal::ExpiredChallenge => "The coordinator refused to register this device: the pairing link expired, was already used or changed. Pair again with the coordinator address.",
                Refusal::RateLimited => "The coordinator refused to register this device: it has reached its sign-up or request limit. Try again later.",
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
                DraftRefusal::NoSingleNote => "Payment draft refused: it needs more notes than one payment can spend.",
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
            Event::WitnessChangeNoticed => ("The coordinator changed its nonce witnesses. LokiSigner keeps using the saved ones until you approve the change.", Kind::Info),
            Event::WitnessChangeKept => ("You kept the current nonce witnesses.", Kind::Info),
            Event::WitnessChangeTrusted => ("You approved the coordinator's new nonce witnesses with Touch ID.", Kind::Info),
            Event::PairingRequested => ("Asked the coordinator for a pairing link.", Kind::Info),
            Event::PairingRefused(reason) => (match reason {
                PairingRefusal::RateLimited => "Pairing refused: the coordinator is rate limiting new pairings.",
                PairingRefusal::SlotsFull => "Pairing refused: the coordinator is full or has too many pairings waiting.",
                PairingRefusal::SlotHeld => "Pairing refused: the coordinator is holding this slot.",
                PairingRefusal::SlotRegistered => "Pairing refused: another member registered this coordinator slot.",
                PairingRefusal::Unreachable => "Pairing failed: LokiSigner couldn’t reach the coordinator.",
                PairingRefusal::Other => "Pairing refused by the coordinator.",
            }, Kind::Error),
            Event::ChallengeRenewed => ("The pairing link expired before registration finished; LokiSigner asked the coordinator for a new one.", Kind::Info),
        }
    }

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
            Event::PairingRequested, Event::ChallengeRenewed,
        ];
        for reason in [Refusal::ExpiredClaim, Refusal::ExpiredChallenge, Refusal::RateLimited, Refusal::SlotTaken, Refusal::WrongSlot, Refusal::Other] {
            events.push(Event::RegistrationRefused(reason));
        }
        for reason in [DraftRefusal::WaitingForConfirmations, DraftRefusal::NoSingleNote, DraftRefusal::InsufficientFunds, DraftRefusal::Other] {
            events.push(Event::DraftRefused(reason));
        }
        for reason in [PairingRefusal::RateLimited, PairingRefusal::SlotsFull, PairingRefusal::SlotHeld, PairingRefusal::SlotRegistered, PairingRefusal::Unreachable, PairingRefusal::Other] {
            events.push(Event::PairingRefused(reason));
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
