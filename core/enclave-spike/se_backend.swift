import Darwin
import Foundation
import LocalAuthentication
import os
import Security

// C-ABI Secure Enclave backend for loki's `SecureElement` trait
// (core/src/signer/secure_element.rs). The Enclave is P-256 only, so it holds the KEK and
// wraps/unwraps the per-share DEK via ECIES (X9.63 KDF + AES-GCM); the FROST share itself
// never enters the Enclave.
//
// Two key lifetimes behind the SAME wrap/unwrap surface:
//   - EPHEMERAL  (se_open_ephemeral): kSecAttrIsPermanent=false, no keychain, no signing
//     identity needed. Works offline, unsigned, today — this is what the FFI verifier runs.
//   - PERSISTENT (se_open_persistent): kSecAttrIsPermanent=true + kSecAttrApplicationTag,
//     biometric access control (.biometryCurrentSet | .privateKeyUsage). Needs the binary
//     signed with an Apple Team ID (free personal team is enough); unsigned it returns
//     errSecMissingEntitlement (-34018). Gated here, not reachable on this unsigned build.
//
// Error codes returned to Rust (negative = failure, >=0 = byte count written):
//   -1 no key handle          -2 ECIES encrypt failed      -3 output buffer too small
//   -4 other key operation failure   -5 key create failed   -6 key missing
//   -7 access-control build    -8 unknown handle           -9 ECDSA sign failed
//   -10 public-key export failed   -11 cancelled   -12 authentication failed
//   -13 biometry locked out   -14 interaction unavailable   -15 biometry unavailable
//   -16 no enrollment   -17 invalidated   -18 accessory disconnected   -19 accessory not paired
//   -20 authentication failed with no recorded enrollment state
//   -21 enrollment changed during restore

private let algo = SecKeyAlgorithm.eciesEncryptionCofactorX963SHA256AESGCM
// ECDSA over SHA-256 of the message, ASN.1/DER (X9.62) output — the device login-challenge
// signature. The same Enclave key signs and wraps; no usage flag restricts it.
private let sigAlgo = SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256

// Opaque handle table: Rust holds a u64, Swift owns the key and any scoped authorization.
private var table: [UInt64: (key: SecKey, biometry: Data?, payment: LAContext?)] = [:]
private var nextHandle: UInt64 = 1
private let lock = NSLock()

private func store(_ k: SecKey, biometry: Data? = nil, payment: LAContext? = nil) -> UInt64 {
    lock.lock(); defer { lock.unlock() }
    let h = nextHandle; nextHandle += 1; table[h] = (k, biometry, payment); return h
}
private func fetch(_ h: UInt64) -> (key: SecKey, biometry: Data?, payment: LAContext?)? {
    lock.lock(); defer { lock.unlock() }
    return table[h]
}

// MARK: - Ephemeral key (unsigned-safe)

@_cdecl("se_open_ephemeral")
public func se_open_ephemeral(_ outHandle: UnsafeMutablePointer<UInt64>) -> Int {
    guard let ac = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        [.privateKeyUsage], nil
    ) else { return -7 }
    let attrs: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits as String: 256,
        kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
        kSecPrivateKeyAttrs as String: [
            kSecAttrIsPermanent as String: false,
            kSecAttrAccessControl as String: ac,
        ],
    ]
    guard let k = SecKeyCreateRandomKey(attrs as CFDictionary, nil) else { return -5 }
    outHandle.pointee = store(k)
    return 0
}

// MARK: - Persistent + biometric key (REQUIRES a signed binary — gated, not run unsigned)

func persistentLookupResult(_ status: OSStatus, createIfMissing: Bool) -> Int? {
    switch status {
    case errSecSuccess: return 0
    case errSecItemNotFound: return createIfMissing ? nil : -6
    case errSecUserCanceled: return -11
    case errSecAuthFailed: return -12
    case errSecInteractionNotAllowed, errSecInteractionRequired: return -14
    default: return -4
    }
}

private func biometricFailure(_ error: NSError?) -> Int? {
    guard let error, error.domain == LAError.errorDomain else { return nil }
    switch LAError.Code(rawValue: error.code) {
    case .userCancel, .systemCancel, .appCancel: return -11
    case .authenticationFailed: return -12
    case .biometryLockout: return -13
    case .notInteractive: return -14
    case .biometryNotAvailable: return -15
    case .biometryNotEnrolled: return -16
    case .biometryDisconnected: return -18
    case .biometryNotPaired: return -19
    default: return nil
    }
}

struct Biometry {
    let state: Data?
    let failure: Int?
}

private func readBiometry() -> Biometry {
    let context = LAContext()
    var error: NSError?
    _ = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
    let state: Data?
    // Don't compare hashes across the two API formats after an OS upgrade.
    if #available(macOS 15, *) {
        state = context.domainState.biometry.stateHash.map { Data([2]) + $0 }
    } else {
        state = context.evaluatedPolicyDomainState.map { Data([1]) + $0 }
    }
    return Biometry(state: state, failure: biometricFailure(error))
}

func keyOperationFailure(_ failure: NSError?, fallback: Int) -> Int {
    var error = failure
    var result = fallback
    var invalidated = false
    while let current = error {
        if let code = biometricFailure(current) {
            if code == -11 || code == -13 { return code }
            result = code
        } else if current.domain == NSOSStatusErrorDomain {
            if let code = persistentLookupResult(OSStatus(truncatingIfNeeded: current.code), createIfMissing: false),
               code != 0, code != -4 {
                if code == -11 { return code }
                result = code
            }
        } else if current.domain == "CryptoTokenKit",
                  (current.userInfo["AKSError"] as? NSNumber)?.uint32Value == 0xe007c009 {
            // Apple's DTS identifies this keybag error as an unusable key after a
            // biometryCurrentSet change. A generic authentication failure is not proof.
            invalidated = true
        }
        error = current.userInfo[NSUnderlyingErrorKey] as? NSError
    }
    return invalidated ? -17 : result
}

func checkedBiometricFailure(_ code: Int, recorded: Data?, current: () -> Biometry) -> Int {
    guard code != -11 && code != -13 && code != -17 else { return code }
    guard let recorded else { return code == -12 ? -20 : code }
    let now = current()
    if now.failure == -13 { return -13 }
    if now.failure == -16 { return -17 }
    if let state = now.state {
        if state.first != recorded.first { return code == -12 ? -20 : code }
        if state != recorded { return -17 }
    }
    return code
}

// An application tag is not a unique Keychain key constraint. Hold one per-user lock
// across lookup and creation, even when two processes are staging the same final path.
private func defaultLockPath() -> String? {
    guard let support = try? FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask,
                                                      appropriateFor: nil, create: true) else { return nil }
    return support.appendingPathComponent(".cash.loki.signer-enclave.lock").path
}

private func creationLock(_ path: String) -> Int32? {
    let fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0o600)
    guard fd >= 0 else { return nil }
    guard flock(fd, LOCK_EX) == 0 else { close(fd); return nil }
    return fd
}

private struct Keychain {
    var lockPath = defaultLockPath
    var lookup: (CFDictionary, UnsafeMutablePointer<CFTypeRef?>?) -> OSStatus = { SecItemCopyMatching($0, $1) }
    var create = createPersistentKey
    var prove = provePersistentKey
    var biometry = readBiometry
    var authorizePayment = authorizePaymentKey
}

#if SE_TESTS
private var keychain = Keychain()
func setTestKeychain(lockPath: @escaping () -> String?,
                     lookup: @escaping (CFDictionary, UnsafeMutablePointer<CFTypeRef?>?) -> OSStatus,
                     create: @escaping (Data) -> (SecKey?, Int), prove: @escaping (SecKey) -> Int,
                     biometry: @escaping () -> Biometry,
                     authorizePayment: @escaping (SecKey, LAContext, LAAccessControlOperation, String) -> Int = authorizePaymentKey) {
    keychain = Keychain(lockPath: lockPath, lookup: lookup, create: create, prove: prove,
                        biometry: biometry, authorizePayment: authorizePayment)
}
#else
private let keychain = Keychain()
#endif

// Only a creating caller with an explicit not-found result may persist a key.
@_cdecl("se_open_persistent")
public func se_open_persistent(_ tagPtr: UnsafePointer<UInt8>, _ tagLen: Int,
                               _ createIfMissing: Int32, _ statePath: UnsafePointer<CChar>?,
                               _ outHandle: UnsafeMutablePointer<UInt64>) -> Int {
    return openPersistent(tagPtr, tagLen, createIfMissing != 0, statePath, nil, outHandle)
}

@_cdecl("se_create_staged")
public func se_create_staged(_ tagPtr: UnsafePointer<UInt8>, _ tagLen: Int,
                             _ statePath: UnsafePointer<CChar>, _ outHandle: UnsafeMutablePointer<UInt64>) -> Int {
    return openPersistent(tagPtr, tagLen, true, statePath, nil, outHandle, staging: true)
}

// Called after the staged store has unwrapped its actual share. The recorded hash was
// sampled before key creation; don't publish unless it is still the same enrollment.
@_cdecl("se_confirm_staged_biometry")
public func se_confirm_staged_biometry(_ handle: UInt64, _ statePath: UnsafePointer<CChar>?) -> Int {
    guard let recorded = fetch(handle)?.biometry else { return -4 }
    let current = keychain.biometry()
    if let failure = current.failure { return failure == -16 ? -21 : failure }
    guard let state = current.state else { return -4 }
    guard state == recorded else { return -21 }
    if let statePath {
        let url = URL(fileURLWithFileSystemRepresentation: statePath, isDirectory: false, relativeTo: nil)
        do { try state.write(to: url, options: .atomic) } catch { return -4 }
    }
    return 0
}

@_cdecl("se_discard_staged")
public func se_discard_staged(_ tagPtr: UnsafePointer<UInt8>, _ tagLen: Int) -> Int {
    // The caller supplies a tag reserved for one restore attempt and one key role.
    let context = LAContext()
    context.interactionNotAllowed = true
    defer { context.invalidate() }
    let query: [String: Any] = [
        kSecClass as String: kSecClassKey,
        kSecAttrApplicationTag as String: Data(bytes: tagPtr, count: tagLen),
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
        kSecUseDataProtectionKeychain as String: true,
        kSecUseAuthenticationContext as String: context,
    ]
    let status = SecItemDelete(query as CFDictionary)
    return status == errSecSuccess || status == errSecItemNotFound ? 0 : -4
}

// Also used for short-lived viewing-key opens; only the reason and handle lifetime differ.
@_cdecl("se_open_payment")
public func se_open_payment(_ tagPtr: UnsafePointer<UInt8>, _ tagLen: Int,
                            _ statePath: UnsafePointer<CChar>?, _ reason: UnsafePointer<CChar>,
                            _ outHandle: UnsafeMutablePointer<UInt64>) -> Int {
    return openPersistent(tagPtr, tagLen, false, statePath, String(cString: reason), outHandle)
}

private func openPersistent(_ tagPtr: UnsafePointer<UInt8>, _ tagLen: Int, _ creating: Bool,
                            _ statePath: UnsafePointer<CChar>?, _ paymentReason: String?,
                            _ outHandle: UnsafeMutablePointer<UInt64>, staging: Bool = false) -> Int {
    let fd: Int32?
    if creating {
        guard let path = keychain.lockPath(), let locked = creationLock(path) else { return -4 }
        fd = locked
    } else {
        fd = nil
    }
    defer { if let fd { close(fd) } }
    let tag = Data(bytes: tagPtr, count: tagLen)
    let stateURL = statePath.map { URL(fileURLWithFileSystemRepresentation: $0, isDirectory: false, relativeTo: nil) }
    let recorded = stateURL.flatMap { try? Data(contentsOf: $0) }.flatMap { data in
        data.count > 1 && (data.first == 1 || data.first == 2) ? data : nil
    }
    // Try to load an existing key by tag first.
    var query: [String: Any] = [
        kSecClass as String: kSecClassKey,
        kSecAttrApplicationTag as String: tag,
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecUseDataProtectionKeychain as String: true,
        kSecReturnRef as String: true,
    ]
    var out: CFTypeRef?
    let status = keychain.lookup(query as CFDictionary, &out)
    if let result = persistentLookupResult(status, createIfMissing: creating) {
        guard result == 0 else { return checkedBiometricFailure(result, recorded: recorded, current: keychain.biometry) }
        guard !staging else { return -4 } // A restore tag is fresh, never a shared or reused key.
        guard let r = out, CFGetTypeID(r) == SecKeyGetTypeID() else { return -4 }
        let key = r as! SecKey
        if let reason = paymentReason {
            let context = LAContext()
            var keep = false
            defer { if !keep { context.invalidate() } }
            // Security's ECIES adaptor performs ECDH on the Enclave key, not a token decrypt.
            let authorized = keychain.authorizePayment(key, context, .useKeyKeyExchange, reason)
            guard authorized == 0 else {
                return checkedBiometricFailure(authorized, recorded: recorded, current: keychain.biometry)
            }
            // Only the explicit evaluation can show UI. Bind the authenticated context
            // to the key reference used for every unwrap in this scope.
            context.interactionNotAllowed = true
            query[kSecUseAuthenticationContext as String] = context
            out = nil
            let status = keychain.lookup(query as CFDictionary, &out)
            let result = persistentLookupResult(status, createIfMissing: false) ?? -4
            guard result == 0 else { return checkedBiometricFailure(result, recorded: recorded, current: keychain.biometry) }
            guard let r = out, CFGetTypeID(r) == SecKeyGetTypeID() else { return -4 }
            outHandle.pointee = store(r as! SecKey, biometry: recorded, payment: context)
            keep = true
            return 0
        }
        if creating {
            let proof = keychain.prove(key)
            guard proof == 0 else {
                return checkedBiometricFailure(proof, recorded: recorded, current: keychain.biometry)
            }
        }
        let state = recorded ?? (creating ? keychain.biometry().state : nil)
        if recorded == nil, let state, let stateURL {
            do { try state.write(to: stateURL, options: .atomic) } catch { return -4 }
        }
        outHandle.pointee = store(key, biometry: state)
        return 0
    }
    // A lookup may stop seeing a key after biometrics change, even with its record still present.
    let missing = checkedBiometricFailure(-6, recorded: recorded, current: keychain.biometry)
    guard missing == -6 else { return missing }
    let before = keychain.biometry()
    if staging {
        if let failure = before.failure { return failure }
        guard before.state != nil else { return -4 }
    }
    let (key, failure) = keychain.create(tag)
    guard let key else {
        // Security can wrap a preflight failure as an undifferentiated auth failure.
        if [-4, -5, -7, -12].contains(failure), let reason = keychain.biometry().failure, reason != -12 { return reason }
        return failure
    }
    let state = before.state ?? keychain.biometry().state
    if let state, let stateURL {
        do { try state.write(to: stateURL, options: .atomic) } catch { return -4 }
    }
    outHandle.pointee = store(key, biometry: state)
    return 0
}

private func authorizePaymentKey(_ key: SecKey, _ context: LAContext, _ operation: LAAccessControlOperation, _ reason: String) -> Int {
    guard let attributes = SecKeyCopyAttributes(key) as NSDictionary?,
          let acl = attributes[kSecAttrAccessControl as String],
          CFGetTypeID(acl as CFTypeRef) == SecAccessControlGetTypeID() else { return -4 }
    let done = DispatchSemaphore(value: 0)
    let result = OSAllocatedUnfairLock(initialState: -4)
    context.evaluateAccessControl(acl as! SecAccessControl, operation: operation,
                                  localizedReason: reason) { success, error in
        result.withLock { $0 = success ? 0 : keyOperationFailure(error as NSError?, fallback: -4) }
        done.signal()
    }
    done.wait()
    return result.withLock { $0 }
}

private func createPersistentKey(_ tag: Data) -> (SecKey?, Int) {
    // Not found: create and persist it, biometric-gated.
    guard let ac = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        [.biometryCurrentSet, .privateKeyUsage], nil
    ) else { return (nil, -7) }
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
    var failure: Unmanaged<CFError>?
    guard let k = SecKeyCreateRandomKey(attrs as CFDictionary, &failure) else {
        return (nil, keyOperationFailure(failure.map { $0.takeRetainedValue() as Error as NSError }, fallback: -5))
    }
    return (k, 0)
}

private func provePersistentKey(_ key: SecKey) -> Int {
    // Public operations can succeed after biometric invalidation. A private operation cannot.
    var failure: Unmanaged<CFError>?
    let challenge = Data("LokiSigner persistent key check".utf8)
    if SecKeyCreateSignature(key, sigAlgo, challenge as CFData, &failure) != nil { return 0 }
    return keyOperationFailure(failure.map { $0.takeRetainedValue() as Error as NSError }, fallback: -9)
}

// MARK: - wrap / unwrap (identical for both lifetimes)

@_cdecl("se_wrap")
public func se_wrap(_ handle: UInt64,
                    _ dek: UnsafePointer<UInt8>, _ dekLen: Int,
                    _ out: UnsafeMutablePointer<UInt8>, _ outCap: Int) -> Int {
    guard let k = fetch(handle)?.key else { return -8 }
    guard let pub = SecKeyCopyPublicKey(k) else { return -1 }
    let data = Data(bytes: dek, count: dekLen)
    guard let ct = SecKeyCreateEncryptedData(pub, algo, data as CFData, nil) as Data? else { return -2 }
    if ct.count > outCap { return -3 }
    ct.copyBytes(to: out, count: ct.count)
    return ct.count
}

@_cdecl("se_unwrap")
public func se_unwrap(_ handle: UInt64,
                      _ ct: UnsafePointer<UInt8>, _ ctLen: Int,
                      _ out: UnsafeMutablePointer<UInt8>, _ outCap: Int) -> Int {
    guard let (k, biometry, _) = fetch(handle) else { return -8 }
    let data = Data(bytes: ct, count: ctLen)
    // Unscoped persistent keys prompt here. Scoped keys already have their authorization.
    var failure: Unmanaged<CFError>?
    guard let pt = SecKeyCreateDecryptedData(k, algo, data as CFData, &failure) as Data? else {
        let code = keyOperationFailure(failure.map { $0.takeRetainedValue() as Error as NSError }, fallback: -4)
        return checkedBiometricFailure(code, recorded: biometry, current: keychain.biometry)
    }
    if pt.count > outCap { return -3 }
    pt.copyBytes(to: out, count: pt.count)
    return pt.count
}

// MARK: - device login key (same Enclave key, ECDSA path)

// Sign `msg` with the Enclave key (ECDSA/SHA-256, DER). On a persistent biometric key this
// prompts Face/Touch ID — proof of user presence for a login challenge. The private op runs
// inside the Secure Enclave; only the signature comes back.
@_cdecl("se_sign")
public func se_sign(_ handle: UInt64,
                    _ msg: UnsafePointer<UInt8>, _ msgLen: Int,
                    _ out: UnsafeMutablePointer<UInt8>, _ outCap: Int) -> Int {
    guard let (k, biometry, payment) = fetch(handle), payment == nil else { return -8 }
    let data = Data(bytes: msg, count: msgLen)
    var failure: Unmanaged<CFError>?
    guard let sig = SecKeyCreateSignature(k, sigAlgo, data as CFData, &failure) as Data? else {
        let code = keyOperationFailure(failure.map { $0.takeRetainedValue() as Error as NSError }, fallback: -9)
        return checkedBiometricFailure(code, recorded: biometry, current: keychain.biometry)
    }
    if sig.count > outCap { return -3 }
    sig.copyBytes(to: out, count: sig.count)
    return sig.count
}

// Export the Enclave key's PUBLIC point as X9.63 uncompressed bytes (04 || X || Y, 65B for
// P-256) — what Loki enrolls and verifies challenge signatures against. The private key never
// leaves the Enclave (SecKeyCopyExternalRepresentation on it would refuse).
@_cdecl("se_public_key")
public func se_public_key(_ handle: UInt64,
                          _ out: UnsafeMutablePointer<UInt8>, _ outCap: Int) -> Int {
    guard let k = fetch(handle)?.key else { return -8 }
    guard let pub = SecKeyCopyPublicKey(k) else { return -1 }
    guard let rep = SecKeyCopyExternalRepresentation(pub, nil) as Data? else { return -10 }
    if rep.count > outCap { return -3 }
    rep.copyBytes(to: out, count: rep.count)
    return rep.count
}

@_cdecl("se_close")
public func se_close(_ handle: UInt64) {
    lock.lock()
    let entry = table.removeValue(forKey: handle)
    lock.unlock()
    entry?.payment?.invalidate()
}
