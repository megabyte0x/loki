use std::{env, fs, path::Path};

use loki_poc::{
    member_state,
    payment_manifest::MAX_INPUTS,
    wallet_store::{PROVIDER_REPORTED, sync_member_wallet},
};
use zcash_client_backend::proto::service::Empty;
use zeroize::Zeroizing;

async fn sync(args: &[String]) -> Result<(), String> {
    if args.len() != 4 {
        return Err("usage: loki_wallet_sync <member-dir> <passphrase-file> <roster.json> <lightwalletd-url>".into());
    }
    let member = member_state::open(
        Path::new(&args[0]),
        Path::new(&args[1]),
        Path::new(&args[2]),
    )?;
    let passphrase =
        Zeroizing::new(fs::read_to_string(&args[1]).map_err(|e| format!("read passphrase: {e}"))?);
    let (mut wallet, mut client) = sync_member_wallet(
        &member,
        Path::new(&args[0]),
        passphrase.trim_end_matches(['\r', '\n']),
        &args[3],
    )
    .await?;
    let height = wallet
        .scanned_height()?
        .ok_or("wallet did not scan any blocks")?;
    let balance = wallet.ironwood_balance_zat()?;
    let chain_tip = client
        .get_lightd_info(Empty {})
        .await
        .map_err(|e| format!("lightwalletd info after scan: {e}"))?
        .into_inner()
        .block_height;
    if chain_tip < u64::from(height) {
        return Err("lightwalletd tip is behind the scanned wallet".into());
    }
    println!(
        "{}",
        serde_json::json!({
            "vault": hex::encode(member.vault),
            "network": member.network.label(),
            "height": height,
            "chain_tip": chain_tip,
            "chain_trust": PROVIDER_REPORTED,
            "balance_zat": balance,
            "max_spendable_zat": wallet.max_spendable(MAX_INPUTS),
        })
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use loki_poc::wallet_store::lightwalletd_endpoint;

    /// Live, network-gated: the configured endpoint reaches a real public Testnet
    /// lightwalletd over TLS and reports the Testnet chain. `LOKI_TEST_LIGHTWALLETD`
    /// overrides the default server. Ignored by default so the suite stays offline.
    #[tokio::test]
    #[ignore = "network: hits a public Testnet lightwalletd"]
    async fn reaches_public_testnet_lightwalletd() {
        use zcash_client_backend::proto::service::{
            compact_tx_streamer_client::CompactTxStreamerClient, Empty,
        };
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let url = std::env::var("LOKI_TEST_LIGHTWALLETD")
            .unwrap_or_else(|_| "https://testnet.zec.rocks:443".into());
        let channel = lightwalletd_endpoint(&url).unwrap().connect().await.unwrap();
        let info = CompactTxStreamerClient::new(channel)
            .get_lightd_info(Empty {})
            .await
            .unwrap()
            .into_inner();
        assert_eq!(info.chain_name, "test");
        assert!(info.block_height > 4_465_026);
    }
}

fn main() {
    let args = env::args().skip(1).collect::<Vec<_>>();
    let result = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("start wallet sync: {e}"))
        .and_then(|runtime| runtime.block_on(sync(&args)));
    if let Err(error) = result {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}
