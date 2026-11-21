![Loki](docs/images/loki-social.png)

> [!WARNING]
> **Testnet only**, Loki is not ready for real funds and refuses mainnet, use disposable
> testnet ZEC.

# Loki

**A shielded Zcash multisig wallet where no single machine can move funds.**

Loki splits a vault's spending key into FROST shares, one per member, and any `t` of the
`n` members must approve and sign a payment together, fewer than `t` cannot spend and no
server ever holds a share.

## How it works

- **Vaults are t-of-n**, any policy with `2 ≤ t < n ≤ 16`.
- **Shares are born on the member's device**, members run a dealerless key generation
  (DKG), each share is created inside that member's signer and never leaves it, and all
  members end up with the same vault address.
- **Members check who they are signing with**, everyone compares a 24-digit roster code
  out of band before keys are generated, so nobody can slip in an extra member.
- **Every signer checks the real transaction**, before signing, each member's signer
  rebuilds the transaction hash from the raw transaction and shows the recipient, amount
  and fee it is about to sign, and anything that doesn't match is refused.
- **The coordinator holds no keys**, it publishes the roster and relays messages, with no
  share, nonce or spend key, so it cannot sign anything on its own.
- **Members only dial out for signing**, all signing traffic goes through a
  [`frostd`](https://github.com/ZcashFoundation/frost) relay that every party connects
  to. A native vault creator also needs a reachable HTTPS peer endpoint for setup.
- **Nonces are single-use**, each signing nonce is claimed at two independent witness
  relays before it is used, so a restored or cloned device cannot sign twice with the same
  nonce.

## Two kinds of signer

| | Native | Browser |
|---|---|---|
| Where the share lives | On the member's machine, on macOS LokiSigner seals it under a Secure Enclave key | In the browser's private storage, sealed under a passkey or passphrase |
| Approving a payment | A native dialog in LokiSigner. Touch ID unlocks the key; it does not approve the payment. | A signer page on its own origin, with a passkey prompt |

The browser signer runs the same signer core compiled to WebAssembly, on a separate origin
from the wallet, and whoever controls the site that serves it could capture the share.

## A payment, end to end

1. A member proposes a payment in the wallet.
2. Every member sees the request, and the first `t` to approve form the signing group.
3. The proposer's app builds the unsigned transaction and sends it to the group.
4. Each signer re-derives what it is signing, shows it and asks its member to approve.
5. Each approving signer produces a signature share, the shares are combined into one
   signature and the transaction is broadcast.

A failed payment can be retried or cancelled, and since a retry spends the same note, at
most one of them is ever mined.

## Try it

On macOS, [build the LokiSigner Flutter app](apps/macos/README.md) to pair,
set up a vault, and use a testnet wallet without a browser.

Build the browser signer once, then run the wallet:

```sh
cd core/loki-signer-wasm && RUSTFLAGS='--cfg getrandom_backend="wasm_js"' wasm-pack build --dev --target web
cd ../wasm-transport    && wasm-pack build --target web
cd ../../web/wallet     && npm install && npm run dev        # http://localhost:3001
```

The signer must be served from its own origin and the relays need CORS for it, see
[`web/wallet/README.md`](web/wallet/README.md) for the full setup,
[`communication/deploy/`](communication/deploy/) for deploy scripts and
[`core/signer-app/README.md`](core/signer-app/README.md) to build the macOS signer.

### Regtest account-link recovery

Follow these steps if `loki_seed_wallet check` reports an identity key or `bind` reports
that the existing profile account key is the identity. Get a fresh challenge for the
affected vault, then run `loki_seed_wallet prove` with the intended regtest wallet's
seed-words file. Before running `bind` with that proof:

- Move the affected member's `secrets/account-link.sealed` to an owner-only backup location
  if present. Leave the member identity and vault files in place.
- Keep `<data-root>/profile/account.sealed` unless `bind` explicitly reports that the
  **profile account key** is the identity. If it does, move that file to an owner-only backup
  location and retry `bind`. Do not move a valid pin to resolve a different-account error.

Run `loki_seed_wallet check` to confirm the new link. The profile pin is shared across vaults;
repeat the rebind with a fresh challenge for each affected vault, using the same wallet.

## Architecture

Every party dials out, secrets stay on member devices, and the shared services only ever
see public or sealed data.

![Loki architecture](docs/images/architecture-map.png)

A payment, from proposal to broadcast:

![A payment, from proposal to broadcast](docs/images/payment-sequence.png)

Built on the Zcash Foundation's audited FROST crates and its `frostd` relay.

## Build and test

```sh
cd core && cargo test --locked --lib
cd web/wallet && npm test
```
