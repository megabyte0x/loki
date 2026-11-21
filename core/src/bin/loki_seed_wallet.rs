//! Reference regtest wallet for proving control of a ZIP 32 Orchard account.
//! This is a wallet-side adapter, not an API that an arbitrary Zcash wallet exposes.
// shortcut: custom RedPallas account proof is regtest only; replace with a reviewed wallet signing capability before custody.

use std::{
    env, fs,
    path::Path,
    process,
    time::{SystemTime, UNIX_EPOCH},
};

use bip39::{Language, Mnemonic};
use blake2b_simd::Params;
use group::ff::Field;
use loki_poc::{setup_transport::Identity, state::MemberDir};
use orchard::keys::{SpendAuthorizingKey, SpendingKey};
use pasta_curves::pallas;
use rand_zp::rand_core::UnwrapErr;
use rand_zp::rngs::SysRng;
use reddsa_frost::{orchard::SpendAuth, Signature, VerificationKey};
use serde_json::{json, Value};
use zeroize::Zeroizing;

// The unique canonical encoding of the Pallas identity.
const PALLAS_IDENTITY: [u8; 32] = [0; 32];

fn now() -> Result<u64, String> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs())
}

fn bytes<const N: usize>(value: &Value, field: &str) -> Result<[u8; N], String> {
    hex::decode(value[field].as_str().ok_or(format!("missing {field}"))?)
        .map_err(|_| format!("invalid {field}"))?
        .try_into()
        .map_err(|_| format!("invalid {field} length"))
}

fn challenge(raw: &[u8], fresh: bool) -> Result<Value, String> {
    let value: Value = serde_json::from_slice(raw).map_err(|e| e.to_string())?;
    if value["version"] != 1
        || value["network"] != "regtest"
        || value["member"]
            .as_u64()
            .is_none_or(|id| !(1..=u64::from(loki_poc::member_state::MAX_MEMBERS)).contains(&id))
    {
        return Err("unsupported account-link challenge".into());
    }
    bytes::<32>(&value, "vault")?;
    bytes::<32>(&value, "identity_signing")?;
    bytes::<32>(&value, "nonce")?;
    let expiry = value["expires_at"].as_u64().ok_or("missing expiry")?;
    if fresh && (expiry < now()? || expiry > now()?.saturating_add(600)) {
        return Err("account-link challenge expired or lasts too long".into());
    }
    Ok(value)
}

fn digest(challenge: &Value) -> [u8; 32] {
    let raw = serde_json::to_vec(challenge).unwrap();
    Params::new()
        .hash_length(32)
        .personal(b"LokiAcctLinkV1")
        .hash(&raw)
        .as_bytes()
        .try_into()
        .unwrap()
}

fn verify(challenge: &Value, proof: &Value) -> Result<[u8; 32], String> {
    if proof["version"] != 1 || proof["account_index"] != 0 {
        return Err("unsupported account proof".into());
    }
    let ak = bytes::<32>(proof, "account_ak")?;
    let key =
        VerificationKey::<SpendAuth>::try_from(ak).map_err(|_| "invalid Orchard account key")?;
    // RedDSA accepts the identity, but it cannot prove control of an account.
    if ak == PALLAS_IDENTITY {
        return Err("Orchard account key is the identity; see README.md for rebind steps".into());
    }
    let signature = Signature::<SpendAuth>::from(bytes::<64>(proof, "signature")?);
    key.verify(&digest(challenge), &signature)
        .map_err(|_| String::from("account proof signature differs from the challenge"))?;
    Ok(ak)
}

fn secret(path: &Path) -> Result<String, String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if fs::metadata(path)
            .map_err(|e| e.to_string())?
            .permissions()
            .mode()
            & 0o077
            != 0
        {
            return Err("secret file must be owner-only (mode 0600)".into());
        }
    }
    fs::read_to_string(path)
        .map(|s| s.trim_end_matches(['\r', '\n']).to_string())
        .map_err(|e| e.to_string())
}

fn prove(args: &[String]) -> Result<(), String> {
    if args.len() != 2 {
        return Err("prove <seed-words-file> <challenge-json-file>".into());
    }
    let c = challenge(&fs::read(&args[1]).map_err(|e| e.to_string())?, true)?;
    let words = Zeroizing::new(secret(Path::new(&args[0]))?);
    let mnemonic = Mnemonic::parse_in(Language::English, words.as_str())
        .map_err(|e| format!("invalid seed words: {e}"))?;
    if mnemonic.word_count() != 24 {
        return Err("reference wallet requires 24 seed words".into());
    }
    let seed = Zeroizing::new(mnemonic.to_seed(""));
    let spending =
        SpendingKey::from_zip32_seed(&seed[..], 1, zip32::AccountId::try_from(0).unwrap())
            .map_err(|e| format!("ZIP 32 account: {e:?}"))?;
    let signer = SpendAuthorizingKey::from(&spending).randomize(&pallas::Scalar::ZERO);
    let raw_signer = reddsa_frost::SigningKey::<SpendAuth>::try_from(<[u8; 32]>::from(&signer))
        .map_err(|_| "invalid Orchard signing scalar")?;
    let key = VerificationKey::<SpendAuth>::from(&raw_signer);
    let ak: [u8; 32] = key.into();
    let sig: [u8; 64] = raw_signer.sign(UnwrapErr(SysRng), &digest(&c)).into();
    println!(
        "{}",
        json!({"version":1,"account_index":0,"account_ak":hex::encode(ak),"signature":hex::encode(sig)})
    );
    Ok(())
}

fn member_identity(member: &Path, pass: &str) -> Result<[u8; 32], String> {
    let raw = MemberDir::open(member, "secrets")
        .read_sealed("identity.sealed", pass)
        .map_err(|e| e.to_string())?;
    Ok(Identity::from_secret_bytes(&raw)?.public().signing)
}

fn check_context(member: &Path, pass: &str, c: &Value) -> Result<(), String> {
    let membership: Value = serde_json::from_slice(
        &fs::read(member.join("membership.json")).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    if membership["vault"] != c["vault"] || membership["slot"] != c["member"] {
        return Err("challenge names another vault membership".into());
    }
    if bytes::<32>(c, "identity_signing")? != member_identity(member, pass)? {
        return Err("challenge names another member identity".into());
    }
    Ok(())
}

fn read_profile_account(profile: &MemberDir, pass: &str) -> Result<Vec<u8>, String> {
    let ak = profile
        .read_sealed("account.sealed", pass)
        .map_err(|e| e.to_string())?;
    if ak == PALLAS_IDENTITY {
        return Err("profile account key is the identity; see README.md for rebind steps".into());
    }
    Ok(ak)
}

fn bind(args: &[String]) -> Result<(), String> {
    if args.len() != 5 {
        return Err(
            "bind <data-root> <member-dir> <passfile> <challenge-json-file> <proof-json-file>"
                .into(),
        );
    }
    let root = Path::new(&args[0]);
    let member = Path::new(&args[1]);
    let pass = Zeroizing::new(secret(Path::new(&args[2]))?);
    let c = challenge(&fs::read(&args[3]).map_err(|e| e.to_string())?, true)?;
    check_context(member, &pass, &c)?;
    let proof: Value = serde_json::from_slice(&fs::read(&args[4]).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let ak = verify(&c, &proof)?;
    let profile = MemberDir::open(root, "profile");
    if profile.exists("account.sealed") {
        if read_profile_account(&profile, &pass)? != ak {
            return Err("this profile is linked to a different account".into());
        }
    } else {
        profile
            .write_sealed("account.sealed", &ak, &pass)
            .map_err(|e| e.to_string())?;
    }
    let store = MemberDir::open(member, "secrets");
    store
        .write_sealed(
            "account-link.sealed",
            &serde_json::to_vec(&json!({"challenge":c,"proof":proof})).unwrap(),
            &pass,
        )
        .map_err(|e| e.to_string())?;
    println!("{}", json!({"account_ak":hex::encode(ak)}));
    Ok(())
}

fn check(args: &[String]) -> Result<(), String> {
    if args.len() != 3 {
        return Err("check <data-root> <member-dir> <passfile>".into());
    }
    let root = Path::new(&args[0]);
    let member = Path::new(&args[1]);
    let pass = Zeroizing::new(secret(Path::new(&args[2]))?);
    let stored = MemberDir::open(member, "secrets")
        .read_sealed("account-link.sealed", &pass)
        .map_err(|_| "this vault has no Zcash account link")?;
    let record: Value = serde_json::from_slice(&stored).map_err(|e| e.to_string())?;
    let c = challenge(&serde_json::to_vec(&record["challenge"]).unwrap(), false)?;
    check_context(member, &pass, &c)?;
    let ak = verify(&c, &record["proof"])?;
    if read_profile_account(&MemberDir::open(root, "profile"), &pass)? != ak {
        return Err("vault membership is linked to another account".into());
    }
    println!(
        "{}",
        json!({"account_ak":hex::encode(ak),"vault":c["vault"]})
    );
    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("prove") => prove(&args[1..]),
        Some("bind") => bind(&args[1..]),
        Some("check") => check(&args[1..]),
        _ => Err("usage: loki_seed_wallet prove|bind|check ...".into()),
    };
    if let Err(error) = result {
        eprintln!("error: {error}");
        process::exit(1);
    }
}
