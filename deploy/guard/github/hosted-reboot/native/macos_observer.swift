import Foundation
import Security
import CryptoKit
import IOKit
import Darwin

// Receipt identity only. No venue, issuer, licence or provider credential ABI.
enum Refused: Error { case refused }
func need(_ ok: Bool) throws { if !ok { throw Refused.refused } }
func sysctlText(_ name: String) throws -> String {
    var length = 0
    try need(sysctlbyname(name, nil, &length, nil, 0) == 0 && length > 1 && length <= 512)
    var data = [CChar](repeating: 0, count: length)
    try need(sysctlbyname(name, &data, &length, nil, 0) == 0)
    try need(length > 1 && length <= data.count && data[length-1] == 0)
    return String(cString: data)
}
func protectedKeychain() throws -> SecKeychain {
    var keychain: SecKeychain?
    try need(SecKeychainOpen("/Library/Keychains/System.keychain", &keychain) == errSecSuccess)
    guard let actual = keychain else { throw Refused.refused }
    return actual
}
func query(_ session: String) throws -> [String: Any] {
    return [kSecClass as String:kSecClassGenericPassword,
            kSecAttrService as String:"zunder.public-reboot.receipt",
            kSecAttrAccount as String:session,
            kSecMatchSearchList as String:[try protectedKeychain()]]
}
func readKey(_ session: String) throws -> Data {
    var q = try query(session)
    q[kSecReturnData as String] = true
    q[kSecMatchLimit as String] = kSecMatchLimitOne
    var output: CFTypeRef?
    try need(SecItemCopyMatching(q as CFDictionary, &output) == errSecSuccess)
    guard let bytes = output as? Data else { throw Refused.refused }
    try need(bytes.count == 32)
    return bytes
}
func facts() throws -> [String: Any] {
    let boot = try sysctlText("kern.bootsessionuuid")
    try need(UUID(uuidString:boot) != nil)
    var time = timeval(); var length = MemoryLayout<timeval>.size
    try need(sysctlbyname("kern.boottime", &time, &length, nil, 0) == 0 && length == MemoryLayout<timeval>.size && time.tv_sec > 0)
    var now = timespec()
    try need(clock_gettime(CLOCK_UPTIME_RAW, &now) == 0 && now.tv_sec >= 0)
    let entry = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOPlatformExpertDevice"))
    try need(entry != 0)
    defer { IOObjectRelease(entry) }
    guard let value = IORegistryEntryCreateCFProperty(entry, "IOPlatformUUID" as CFString, kCFAllocatorDefault, 0)?.takeRetainedValue() as? String else { throw Refused.refused }
    try need(UUID(uuidString:value) != nil && value != "00000000-0000-0000-0000-000000000000")
    var seconds: UInt64 = 0; var micros: UInt64 = 0
    try need(public_reboot_birth(getppid(), &seconds, &micros) == 0)
    let machine = SHA256.hash(data:Data(value.utf8)).map { String(format:"%02x",$0) }.joined()
    return ["schema":1,"kind":"actual-macos-kernel-facts","machine_sha256":machine,"boot_id":boot,
            "boot_time_ms":UInt64(time.tv_sec) * 1000 + UInt64(time.tv_usec) / 1000,
            "uptime_ms":UInt64(now.tv_sec) * 1000 + UInt64(now.tv_nsec) / 1000000,
            "observer_pid":getppid(),"observer_birth":"\(seconds):\(micros)"]
}
do {
    try need(CommandLine.arguments.count == 3 && public_reboot_uid() == 0 && CommandLine.arguments[0].hasPrefix("/"))
    try need(SecKeychainSetUserInteractionAllowed(false) == errSecSuccess)
    let mode = CommandLine.arguments[1], session = CommandLine.arguments[2]
    try need(session.range(of:"^[0-9a-f]{64}$",options:.regularExpression) != nil)
    switch mode {
    case "facts":
        let data = try JSONSerialization.data(withJSONObject:try facts(),options:[.sortedKeys])
        FileHandle.standardOutput.write(data)
    case "store":
        // Anonymous stdin pipe must be supplied by the original bootstrap.
        var inputStat = stat(); try need(fstat(STDIN_FILENO,&inputStat) == 0 && ((inputStat.st_mode & S_IFMT) == S_IFIFO || (inputStat.st_mode & S_IFMT) == S_IFSOCK))
        let seed = try FileHandle.standardInput.read(upToCount:33) ?? Data()
        try need(seed.count == 32)
        var q = try query(session)
        q.removeValue(forKey:kSecMatchSearchList as String)
        q[kSecUseKeychain as String] = try protectedKeychain()
        var application: SecTrustedApplication?
        try need(SecTrustedApplicationCreateFromPath(CommandLine.arguments[0], &application) == errSecSuccess)
        guard let trusted = application else { throw Refused.refused }
        var access: SecAccess?
        try need(SecAccessCreate("Public reboot receipt" as CFString,[trusted] as CFArray,&access) == errSecSuccess)
        guard let acl = access else { throw Refused.refused }
        q[kSecAttrAccess as String] = acl; q[kSecValueData as String] = seed
        try need(SecItemAdd(q as CFDictionary,nil) == errSecSuccess) // duplicate never overwritten
    case "read":
        var outputStat = stat(); try need(fstat(STDOUT_FILENO,&outputStat) == 0 && ((outputStat.st_mode & S_IFMT) == S_IFIFO || (outputStat.st_mode & S_IFMT) == S_IFSOCK))
        FileHandle.standardOutput.write(try readKey(session))
    case "absent":
        var result: CFTypeRef?
        try need(SecItemCopyMatching(try query(session) as CFDictionary,&result) == errSecItemNotFound)
        FileHandle.standardOutput.write(Data("{\"key_store_absent\":true}".utf8))
    case "delete":
        var inputStat = stat()
        try need(fstat(STDIN_FILENO,&inputStat) == 0 && ((inputStat.st_mode & S_IFMT) == S_IFIFO || (inputStat.st_mode & S_IFMT) == S_IFSOCK))
        let expected = try FileHandle.standardInput.read(upToCount:33) ?? Data()
        try need(expected.count == 32)
        var q = try query(session)
        q[kSecReturnData as String] = true
        q[kSecReturnPersistentRef as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var captured: CFTypeRef?
        try need(SecItemCopyMatching(q as CFDictionary,&captured) == errSecSuccess)
        guard let item = captured as? [String:Any], let seed = item[kSecValueData as String] as? Data,
              let reference = item[kSecValuePersistentRef as String] as? Data else { throw Refused.refused }
        try need(seed.count == 32 && !reference.isEmpty)
        let actual = try Curve25519.Signing.PrivateKey(rawRepresentation:seed).publicKey.rawRepresentation
        try need(actual == expected)
        // Delete only the captured persistent item; replacement cannot be selected
        // by a broad service/account query after the original ownership read.
        try need(SecItemDelete([kSecValuePersistentRef as String:reference] as CFDictionary) == errSecSuccess)
        var result: CFTypeRef?
        try need(SecItemCopyMatching(try query(session) as CFDictionary,&result) == errSecItemNotFound)
    default: throw Refused.refused
    }
} catch {
    // Never print input, key bytes, registry identity or provider credentials.
    FileHandle.standardError.write(Data("Public reboot native helper refused\n".utf8)); exit(1)
}
