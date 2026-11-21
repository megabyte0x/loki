import Darwin
import Foundation
import LocalAuthentication
import Security

// Run unsigned: swiftc -D SE_TESTS se_backend.swift se_backend_tests.swift -o <output> && <output>
@main
enum BackendTests {
    static func main() {
        let failures: [(OSStatus, Int)] = [
            (errSecUserCanceled, -11), (errSecAuthFailed, -12),
            (errSecInteractionNotAllowed, -14), (errSecInteractionRequired, -14), (errSecMissingEntitlement, -4),
            (errSecNotAvailable, -4),
        ]
        for creating in [false, true] {
            precondition(persistentLookupResult(errSecSuccess, createIfMissing: creating) == 0)
            for (status, result) in failures {
                precondition(persistentLookupResult(status, createIfMissing: creating) == result)
            }
        }
        precondition(persistentLookupResult(errSecItemNotFound, createIfMissing: false) == -6)
        precondition(persistentLookupResult(errSecItemNotFound, createIfMissing: true) == nil)

        let biometric: [(LAError.Code, Int)] = [
            (.userCancel, -11), (.systemCancel, -11), (.appCancel, -11),
            (.authenticationFailed, -12), (.biometryLockout, -13),
            (.notInteractive, -14), (.biometryNotAvailable, -15), (.biometryNotEnrolled, -16),
            (.biometryDisconnected, -18), (.biometryNotPaired, -19),
        ]
        for (code, result) in biometric {
            let underlying = NSError(domain: LAError.errorDomain, code: code.rawValue)
            let wrapper = NSError(domain: NSOSStatusErrorDomain, code: Int(errSecAuthFailed),
                                  userInfo: [NSUnderlyingErrorKey: underlying])
            precondition(keyOperationFailure(wrapper, fallback: -4) == result)
        }
        let missing = NSError(domain: NSOSStatusErrorDomain, code: Int(errSecItemNotFound))
        precondition(keyOperationFailure(missing, fallback: -4) == -6)
        let invalidated = NSError(domain: "CryptoTokenKit", code: -3,
                                  userInfo: ["AKSError": NSNumber(value: -536362999)])
        precondition(keyOperationFailure(invalidated, fallback: -4) == -17)
        let unrelated = NSError(domain: "CryptoTokenKit", code: -3)
        precondition(keyOperationFailure(unrelated, fallback: -4) == -4)
        entryPoint(failures)
        print("PASS: persistent Keychain entry point, lock, reuse proof, and biometric failure classes (no hardware)")
        paymentScope()
        print("PASS: payment authorization, non-interactive key binding, scope invalidation and cancellation (stand-in)")
    }

    static func entryPoint(_ failures: [(OSStatus, Int)]) {
        let temp = FileManager.default.temporaryDirectory.appendingPathComponent("loki-se-tests-\(UUID())")
        try! FileManager.default.createDirectory(at: temp, withIntermediateDirectories: false)
        defer { try! FileManager.default.removeItem(at: temp) }
        let lockPath = temp.appendingPathComponent("lock").path
        let statePath = temp.appendingPathComponent("biometry-state").path
        let attrs: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                                    kSecAttrKeySizeInBits as String: 256]
        let softwareKey = SecKeyCreateRandomKey(attrs as CFDictionary, nil)!
        let tag = Data("distinct-test-tag".utf8)
        var lookupStatus = errSecItemNotFound
        var lookupValue: CFTypeRef? = nil
        var creationFailure: Int? = nil
        var proof = 0
        var lookups = 0, creations = 0, proofs = 0
        var wantsLock = false
        let enrollment = Data([2, 21, 68])
        var current = Biometry(state: enrollment, failure: nil)

        func lockIsHeld() -> Bool {
            let fd = open(lockPath, O_RDWR | O_CREAT, 0o600)
            precondition(fd >= 0)
            defer { close(fd) }
            let result = flock(fd, LOCK_EX | LOCK_NB)
            precondition(result == 0 || errno == EWOULDBLOCK)
            return result != 0
        }
        setTestKeychain(lockPath: { lockPath }, lookup: { query, result in
            precondition((query as NSDictionary)[kSecAttrApplicationTag as String] as? Data == tag)
            precondition(lockIsHeld() == wantsLock, "lookup must be inside the creation lock, and only on create")
            lookups += 1
            result?.pointee = lookupValue
            return lookupStatus
        }, create: { actualTag in
            precondition(lockIsHeld() && actualTag == tag)
            creations += 1
            if let failure = creationFailure { return (nil, failure) }
            return (softwareKey, 0)
        }, prove: { _ in
            precondition(lockIsHeld())
            proofs += 1
            return proof
        }, biometry: { current })

        func run(_ create: Bool, _ expected: Int) {
            let before = lookups
            wantsLock = create
            var handle: UInt64 = 0
            let status = tag.withUnsafeBytes { bytes in
                statePath.withCString { path in
                    se_open_persistent(bytes.bindMemory(to: UInt8.self).baseAddress!, tag.count,
                                       create ? 1 : 0, path, &handle)
                }
            }
            precondition(status == expected && lookups == before + 1)
            precondition((handle != 0) == (status == 0))
            if handle != 0 { se_close(handle) }
            precondition(!lockIsHeld(), "creation must release the lock on success and error")
        }
        run(false, -6)
        for (status, failure) in failures {
            lookupStatus = status
            let expected = failure == -12 ? -20 : failure // No recorded state yet.
            run(false, expected)
            run(true, expected)
        }
        lookupStatus = errSecSuccess
        lookupValue = "not a key" as NSString
        run(true, -4)
        precondition(creations == 0 && proofs == 0)

        lookupStatus = errSecItemNotFound
        creationFailure = -12
        current = Biometry(state: nil, failure: -16)
        run(true, -16)
        creationFailure = nil
        current = Biometry(state: enrollment, failure: nil)
        run(true, 0)
        precondition((try! Data(contentsOf: URL(fileURLWithPath: statePath))) == enrollment)
        precondition(creations == 2 && proofs == 0)

        lookupStatus = errSecSuccess
        lookupValue = softwareKey
        run(false, 0)
        precondition(proofs == 0, "opening must not prompt for a private-key proof")
        run(true, 0)
        precondition(proofs == 1)
        proof = -14
        run(true, -14) // interaction blocked is not evidence of invalidation
        proof = -12
        run(true, -12) // a failed match with unchanged enrollment is retryable
        current = Biometry(state: Data([2, 68, 21]), failure: nil)
        run(true, -17)
        proof = -11
        run(true, -11)
        proof = -13
        run(true, -13)
        precondition(creations == 2 && proofs == 6)

        lookupStatus = errSecItemNotFound
        run(false, -17)
        run(true, -17)
        lookupStatus = errSecAuthFailed
        run(false, -17)
        current = Biometry(state: Data([1, 68, 21]), failure: nil)
        run(false, -20) // different APIs aren't comparable
        current = Biometry(state: nil, failure: -15)
        run(false, -12) // closed lid is not proof of new fingerprints
        current = Biometry(state: nil, failure: -16)
        run(false, -17) // all fingerprints removed
        try! FileManager.default.removeItem(atPath: statePath)
        run(false, -20) // a legacy profile lacks evidence of invalidation
        precondition(creations == 2)
    }

    static func paymentScope() {
        let key = SecKeyCreateRandomKey([
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
        ] as CFDictionary, nil)!
        let reason = "unlock signing for 0.40000000 ZEC to utest1abcdefgh…ij23456789"
        var contexts = [LAContext]()
        var bound = 0
        var cancel = false
        setTestKeychain(lockPath: { fatalError("a payment cannot create a key") }, lookup: { query, out in
            if let context = (query as NSDictionary)[kSecUseAuthenticationContext as String] as? LAContext {
                precondition(!cancel && context === contexts.last && context.interactionNotAllowed)
                bound += 1
            }
            out?.pointee = key
            return errSecSuccess
        }, create: { _ in fatalError("a payment cannot create a key") },
           prove: { _ in fatalError("a payment cannot ask for an ECDSA proof") },
           biometry: { fatalError("a cancellation must not be reclassified") },
           authorizePayment: { _, context, operation, text in
               precondition(operation == .useKeyKeyExchange, "ECIES needs key exchange, not decrypt")
               precondition(text == reason && !context.interactionNotAllowed)
               precondition(!contexts.contains { $0 === context })
               contexts.append(context)
               return cancel ? -11 : 0
           })

        func sign(_ handle: UInt64) -> Int {
            var output = [UInt8](repeating: 0, count: 128)
            return [UInt8(42)].withUnsafeBufferPointer { msg in
                output.withUnsafeMutableBufferPointer { sig in
                    se_sign(handle, msg.baseAddress!, msg.count, sig.baseAddress!, sig.count)
                }
            }
        }
        var unscoped: UInt64 = 0
        precondition([UInt8(1)].withUnsafeBufferPointer { tag in
            se_open_persistent(tag.baseAddress!, tag.count, 0, nil, &unscoped)
        } == 0)
        precondition(sign(unscoped) > 0, "the stand-in key can sign without a scope")
        se_close(unscoped)

        for expected in [0, 0, -11] {
            cancel = expected != 0
            var handle: UInt64 = 0
            let rc = reason.withCString { text in
                [UInt8(1)].withUnsafeBufferPointer { tag in
                    se_open_payment(tag.baseAddress!, tag.count, nil, text, &handle)
                }
            }
            precondition(rc == expected && (handle != 0) == !cancel)
            if handle != 0 {
                precondition(sign(handle) == -8, "a scoped unwrap handle must never sign a login challenge")
                se_close(handle)
            }
            var error: NSError?
            precondition(!contexts.last!.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error))
            precondition(error?.code == LAError.Code.invalidContext.rawValue)
        }
        precondition(contexts.count == 3 && bound == 2)
    }
}
