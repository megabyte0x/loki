import Foundation
import Security

// Minimal signer-app proof: a PERSISTENT Secure Enclave key that wraps/unwraps the
// signer DEK. Runs inside a provisioned app, so the keychain-access-groups entitlement
// is profile-backed and persistent SE keys are allowed.
//
//   LokiSigner persist     -> create at init + reload (no biometric; headless-verifiable)
//   LokiSigner biometric   -> create + unwrap gated by Touch ID (interactive)
//   LokiSigner approve     -> real DKG + payment gated by the native approval dialog

let mode = CommandLine.arguments.dropFirst().first ?? "native"
if mode == "native" {
    let args = Array(CommandLine.arguments.dropFirst(2))
    guard !args.contains(where: { $0.hasPrefix("loki://") || $0 == "--pairing-url" }) else {
        FileHandle.standardError.write(Data("Open pairing links in the wallet, not in command arguments.\n".utf8))
        exit(2)
    }
    // Apple events are the normal handoff; automation may pipe one line on private stdin.
    let link = args.contains("--pairing-stdin") ? readLine() : nil
    SignerLog.start()
    runNativeSigner(arguments: args.filter { $0 != "--pairing-stdin" }, link: link)
}
if mode == "approve" {
    runApprovalSelftest()
}
if !["persist", "biometric", "rust", "member", "serve"].contains(mode) {
    FileHandle.standardError.write(Data("Unknown mode; use native, serve, approve, rust, member, persist or biometric. Open pairing links in the wallet.\n".utf8))
    exit(2)
}
let biometric = (mode == "biometric")
let tag = "cash.loki.signer.kek.app".data(using: .utf8)!

// `rust` mode: the ACTUAL loki signer (linked as libloki_poc.a) seals its FROST share under
// a PERSISTENT Secure Enclave key and reloads it — the real native-signer path.
@_silgen_name("loki_signer_enclave_selftest")
func loki_signer_enclave_selftest() -> Int32

@_silgen_name("loki_signer_enclave_dkg_member_selftest")
func loki_signer_enclave_dkg_member_selftest() -> Int32

// `serve` mode: run the LIVE member-app signer with the member's FROST share held in the Secure
// Enclave, joining a vault over frostd. Args after `serve` are the member flags (--data, --port,
// --frostd-url, --advertise-url, --peer, ...). Blocks until the process is stopped.
@_silgen_name("loki_member_app_serve")
func loki_member_app_serve() -> Int32

if mode == "serve" {
    exit(loki_member_app_serve())
}

if mode == "rust" {
    let rc = loki_signer_enclave_selftest()
    if rc == 0 {
        print("RUST SIGNER ENCLAVE PASS: FROST share sealed + reloaded under the persistent Secure Enclave key")
        exit(0)
    }
    FileHandle.standardError.write("RUST SELFTEST FAILED (code \(rc))\n".data(using: .utf8)!)
    exit(rc)
}

// `member` mode: the full native-member lifecycle — a 2-of-3 vault created by real v2 DKG with
// every share generated + sealed under its own PERSISTENT Secure Enclave key, then a quorum
// signs a payment. The persistent counterpart of the ephemeral `cargo test`.
if mode == "member" {
    let rc = loki_signer_enclave_dkg_member_selftest()
    if rc == 0 {
        print("RUST SIGNER ENCLAVE MEMBER PASS: real DKG + payment through persistent Secure Enclave keys")
        exit(0)
    }
    FileHandle.standardError.write("RUST MEMBER SELFTEST FAILED (code \(rc))\n".data(using: .utf8)!)
    exit(rc)
}

func fail(_ m: String) -> Never { FileHandle.standardError.write(("FAIL: "+m+"\n").data(using:.utf8)!); exit(1) }

func wipe() {
    SecItemDelete([kSecClass as String: kSecClassKey,
                   kSecAttrApplicationTag as String: tag,
                   kSecUseDataProtectionKeychain as String: true] as CFDictionary)
}

func createKey() -> SecKey {
    let flags: SecAccessControlCreateFlags = biometric ? [.privateKeyUsage, .biometryCurrentSet]
                                                       : [.privateKeyUsage]
    guard let ac = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags, nil
    ) else { fail("access control") }
    let attrs: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits as String: 256,
        kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
        kSecUseDataProtectionKeychain as String: true,
        kSecPrivateKeyAttrs as String: [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: tag,
            kSecAttrAccessControl as String: ac,
        ],
    ]
    var err: Unmanaged<CFError>?
    guard let k = SecKeyCreateRandomKey(attrs as CFDictionary, &err) else {
        fail("create persistent SE key: \(err!.takeRetainedValue())")
    }
    return k
}

func loadKey() -> SecKey {
    let q: [String: Any] = [
        kSecClass as String: kSecClassKey,
        kSecAttrApplicationTag as String: tag,
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecUseDataProtectionKeychain as String: true,
        kSecReturnRef as String: true,
    ]
    var out: CFTypeRef?
    let s = SecItemCopyMatching(q as CFDictionary, &out)
    guard s == errSecSuccess, let r = out else { fail("reload SE key: OSStatus \(s)") }
    return (r as! SecKey)
}

let algo = SecKeyAlgorithm.eciesEncryptionCofactorX963SHA256AESGCM
wipe()

// INIT: create + persist the Enclave KEK, wrap a random DEK.
let created = createKey()
guard let pub = SecKeyCopyPublicKey(created) else { fail("pub") }
var dek = Data(count: 32)
_ = dek.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
guard let wrapped = SecKeyCreateEncryptedData(pub, algo, dek as CFData, nil) as Data? else { fail("wrap") }
print("OK  init: persistent Secure Enclave KEK created\(biometric ? " (biometric-gated)" : ""); DEK wrapped \(wrapped.count)B")

// NEXT LAUNCH: reload the SAME key by tag, unwrap (biometric mode triggers Touch ID here).
let reloaded = loadKey()
guard let got = SecKeyCreateDecryptedData(reloaded, algo, wrapped as CFData, nil) as Data? else { fail("unwrap after reload") }
guard got == dek else { fail("round-trip mismatch after reload") }
print("OK  reload: SAME Enclave key fetched by tag; DEK recovered byte-for-byte")

wipe()
print("SIGNER-APP ENCLAVE PASS: persistent\(biometric ? " + Touch-ID" : "") wrap/unwrap of a signer DEK")
exit(0)
