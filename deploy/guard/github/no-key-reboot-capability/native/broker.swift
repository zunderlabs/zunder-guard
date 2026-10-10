import Foundation
import CryptoKit
import Darwin
import IOKit

// This carrier reports observations only. No release/runtime/private authority is produced.
let base = "/Library/ZunderGitHubRebootCapability"
let plistPath = "/Library/LaunchDaemons/com.zunder.github-reboot-capability.plist"
let label = "com.zunder.github-reboot-capability"
let repo = "zunderlabs/zunder-guard"
let checkName = "No-key original Mac reboot capability"
let deniedAuthority:[String:Any]=["sourceAdmitted":false,"runtimeAdmitted":false,"nativeReleaseAccepted":false,"releaseReady":false,"privateCustodyProven":false,"wholeResourceCleanupProven":false]
enum Refusal: Error { case closed }
func require(_ value: Bool) throws { if !value { throw Refusal.closed } }
func digest(_ data: Data) -> String { SHA256.hash(data: data).map { String(format:"%02x",$0) }.joined() }
func encoded(_ value: Any) throws -> Data { try JSONSerialization.data(withJSONObject:value,options:[.sortedKeys,.withoutEscapingSlashes]) }
func object(_ data: Data, _ keys: Set<String>) throws -> [String:Any] {
    try require(data.count <= 32768)
    guard let o = try JSONSerialization.jsonObject(with:data) as? [String:Any] else { throw Refusal.closed }
    try require(Set(o.keys) == keys && (try encoded(o)) == data) // Duplicate/noncanonical JSON refused.
    return o
}
func number(_ o:[String:Any],_ name:String) throws -> Int64 {
    guard let n=o[name] as? NSNumber, CFGetTypeID(n) != CFBooleanGetTypeID() else { throw Refusal.closed }
    let v=n.int64Value; try require(v>=0 && n.doubleValue==Double(v) && v<=9007199254740991); return v
}
func text(_ o:[String:Any],_ name:String) throws -> String { guard let s=o[name] as? String else { throw Refusal.closed }; return s }
func matches(_ s:String,_ pattern:String) -> Bool { s.range(of:pattern,options:.regularExpression) != nil }
func wall() -> Int64 { Int64(Date().timeIntervalSince1970 * 1000) }
func mono() throws -> Int64 { var t=timespec(); try require(clock_gettime(CLOCK_UPTIME_RAW,&t)==0 && t.tv_sec>=0); return Int64(t.tv_sec)*1000+Int64(t.tv_nsec)/1000000 }
func bootText() throws -> String {
    var count=0;try require(sysctlbyname("kern.bootsessionuuid",nil,&count,nil,0)==0 && count>1 && count<=512)
    var bytes=[CChar](repeating:0,count:count); try require(sysctlbyname("kern.bootsessionuuid",&bytes,&count,nil,0)==0 && bytes[count-1]==0)
    let s=String(cString:bytes).lowercased();try require(UUID(uuidString:s) != nil); return s
}
func nativeFacts() throws -> [String:Any] {
    let w=wall();var boot=timeval();var size=MemoryLayout<timeval>.size
    try require(sysctlbyname("kern.boottime",&boot,&size,nil,0)==0 && size==MemoryLayout<timeval>.size && boot.tv_sec>0 && boot.tv_usec>=0 && boot.tv_usec<1000000)
    let service=IOServiceGetMatchingService(kIOMainPortDefault,IOServiceMatching("IOPlatformExpertDevice"));try require(service != 0);defer { IOObjectRelease(service) }
    guard let raw=IORegistryEntryCreateCFProperty(service,"IOPlatformUUID" as CFString,kCFAllocatorDefault,0)?.takeRetainedValue() as? String else { throw Refusal.closed }
    try require(UUID(uuidString:raw) != nil && raw != "00000000-0000-0000-0000-000000000000")
    var sec:UInt64=0,usec:UInt64=0;let pid=getpid();try require(capability_birth(pid,&sec,&usec)==1)
    let birth=Int64(sec)*1000+Int64(usec)/1000,b=Int64(boot.tv_sec)*1000+Int64(boot.tv_usec)/1000,up=try mono()
    try require(b<=birth && birth<=w && up<=w-b+5000)
    return ["machine":digest(Data(raw.lowercased().utf8)),"boot":try bootText(),"boot_ms":b,"uptime_ms":up,"pid":Int64(pid),"birth_ms":birth]
}
func parentGuard(_ path:String) throws {
    let parents = path==plistPath ? ["/","/Library","/Library/LaunchDaemons"] : ["/","/Library",base]
    for p in parents { var s=stat();try require(lstat(p,&s)==0 && (s.st_mode&S_IFMT)==S_IFDIR && s.st_uid==0 && (s.st_mode&0o022)==0);if p==base {try require((s.st_mode&0o7777)==0o700)} }
}
final class Retained {
    let path:String; let fd:Int32; let info:stat; let data:Data
    init(_ path:String,_ mode:mode_t, _ allowEmpty:Bool=false) throws {
        try parentGuard(path);var before=stat();try require(lstat(path,&before)==0)
        let f=open(path,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);try require(f>=0);fd=f;self.path=path
        var s=stat(); do {
            try require(fstat(f,&s)==0 && s.st_dev==before.st_dev && s.st_ino==before.st_ino && (s.st_mode&S_IFMT)==S_IFREG && s.st_uid==0 && s.st_nlink==1 && (s.st_mode&0o7777)==mode && s.st_size>=0 && s.st_size<=4194304 && (allowEmpty || s.st_size>0))
            var d=Data(count:Int(s.st_size));let length=d.count;let received=d.withUnsafeMutableBytes { read(f,$0.baseAddress,length) };try require(received==d.count)
            var after=stat();try require(fstat(f,&after)==0 && after.st_mtimespec.tv_sec==s.st_mtimespec.tv_sec && after.st_mtimespec.tv_nsec==s.st_mtimespec.tv_nsec && after.st_size==s.st_size)
            info=s;data=d
        } catch {close(f);throw error}
    }
    deinit {close(fd)}
    var identity:[String:Any] { ["dev":Int64(info.st_dev),"ino":Int64(info.st_ino),"mode":Int64(info.st_mode&0o7777),"sha":digest(data)] }
    func unchanged() throws {
        try parentGuard(path);var s=stat();try require(lstat(path,&s)==0 && s.st_dev==info.st_dev && s.st_ino==info.st_ino && s.st_uid==0 && s.st_nlink==1 && s.st_mode==info.st_mode)
        let current=try Retained(path,info.st_mode&0o7777);try require(current.identity as NSDictionary == identity as NSDictionary)
    }
    func remove() -> String { do {_ = try boundedRemaining();try unchanged();try require(unlink(path)==0);var s=stat();try require(lstat(path,&s) != 0 && errno==ENOENT);return "ABSENT_OBSERVED"} catch {return "UNKNOWN"} }
}
var createdFiles:[String:Retained] = [:]
var baseIdentity:(dev_t,ino_t)? = nil
var terminalFiles:[String:Retained] = [:]
var bootstrapSucceeded=false
func cleanupTerminal() {
    guard (try? boundedRemaining()) != nil else {return}
    for f in terminalFiles.values {_ = f.remove()}
    for f in createdFiles.values {_ = f.remove()}
    if bootstrapSucceeded {try? fixedProcess("/bin/launchctl",["bootout","system/"+label])}
    // Directory absence is not asserted; foreign/unmeasured contents are retained.
    if let identity=baseIdentity {var current=stat();if lstat(base,&current)==0 && (current.st_mode&S_IFMT)==S_IFDIR && current.st_uid==0 && (current.st_mode&0o7777)==0o700 && current.st_dev==identity.0 && current.st_ino==identity.1 {_ = rmdir(base)}}
}
func create(_ path:String,_ data:Data,_ mode:mode_t) throws {
    try parentGuard(path);let fd=open(path,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,mode);try require(fd>=0);defer {close(fd)}
    try require(fchmod(fd,mode)==0);let n=data.withUnsafeBytes { write(fd,$0.baseAddress,data.count) };try require(n==data.count && fsync(fd)==0)
    let retained=try Retained(path,mode);try require(retained.data==data);createdFiles[path]=retained
}
var cleanupWallDeadline:Int64 = 0
var cleanupMonoDeadline:Int64? = nil
func boundedRemaining() throws -> Int64 {
    let w=wall();try require(cleanupWallDeadline>0 && w<cleanupWallDeadline)
    var left=cleanupWallDeadline-w
    if let bound=cleanupMonoDeadline {left=min(left,bound-(try mono()))}
    try require(left>0);return left
}
func fixedProcess(_ path:String,_ args:[String]) throws {
    let allowance=min(5000,try boundedRemaining()),start=try mono()
    let p=Process();p.executableURL=URL(fileURLWithPath:path);p.arguments=args;p.environment=["PATH":"/usr/bin:/bin:/usr/sbin:/sbin","LANG":"C"];p.standardOutput=FileHandle.nullDevice;p.standardError=FileHandle.nullDevice
    try p.run()
    while p.isRunning {if (try mono())-start>=allowance {p.terminate();throw Refusal.closed};usleep(10000)}
    try require(p.terminationStatus==0)
}
func plist(_ configHash:String) -> Data {
    Data(("<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\"><plist version=\"1.0\"><dict><key>Label</key><string>"+label+"</string><key>ProgramArguments</key><array><string>"+base+"/broker</string><string>watch</string><string>"+configHash+"</string></array><key>RunAtLoad</key><true/><key>UserName</key><string>root</string><key>StandardOutPath</key><string>/dev/null</string><key>StandardErrorPath</key><string>/dev/null</string></dict></plist>\n").utf8)
}
func signed(_ value:[String:Any],_ key:Curve25519.Signing.PrivateKey) throws -> [String:Any] { let data=try encoded(value);return ["payload":data.base64EncodedString(),"signature":try key.signature(for:data).base64EncodedString()] }
func createRegistration(_ id:Int64,_ pre:[String:Any],_ key:Curve25519.Signing.PrivateKey) throws {
    let path=base+"/registration";try parentGuard(path)
    let fd=open(path,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0o600);try require(fd>=0);defer {close(fd)}
    var info=stat();try require(fchmod(fd,0o600)==0 && fstat(fd,&info)==0 && (info.st_mode&S_IFMT)==S_IFREG && info.st_uid==0 && info.st_nlink==1)
    // Inode identity may be signed inside its own contents; no circular self-hash is used.
    let identity:[String:Any]=["dev":Int64(info.st_dev),"ino":Int64(info.st_ino),"mode":384]
    let bytes=try encoded(signed(["schema":1,"id":id,"preboot":pre,"identity":identity],key))
    try require(bytes.withUnsafeBytes {write(fd,$0.baseAddress,bytes.count)}==bytes.count && fsync(fd)==0)
    let retained=try Retained(path,0o600);try require(retained.data==bytes && retained.info.st_dev==info.st_dev && retained.info.st_ino==info.st_ino);createdFiles[path]=retained
}
func verified(_ value:[String:Any],_ key:Curve25519.Signing.PublicKey,_ fields:Set<String>) throws -> [String:Any] {
    try require(Set(value.keys)==["payload","signature"])
    guard let data=Data(base64Encoded:try text(value,"payload")),let signature=Data(base64Encoded:try text(value,"signature")) else {throw Refusal.closed}
    try require(key.isValidSignature(signature,for:data));return try object(data,fields)
}
func api(_ method:String,_ suffix:String,_ token:String,_ body:[String:Any]?,_ timeout:Double) throws -> [String:Any] {
    try require(timeout>0 && timeout<=5 && (suffix=="" || matches(suffix,"^/[1-9][0-9]{0,17}$")))
    var request=URLRequest(url:URL(string:"https://api.github.com/repos/"+repo+"/check-runs"+suffix)!,timeoutInterval:timeout)
    request.httpMethod=method;request.setValue("Bearer "+token,forHTTPHeaderField:"Authorization");request.setValue("application/vnd.github+json",forHTTPHeaderField:"Accept");request.setValue("2022-11-28",forHTTPHeaderField:"X-GitHub-Api-Version");request.setValue("application/json",forHTTPHeaderField:"Content-Type");if let body=body {request.httpBody=try encoded(body)}
    let semaphore=DispatchSemaphore(value:0);let box=ResponseBox()
    let session=URLSession(configuration:.ephemeral,delegate:NoRedirect(),delegateQueue:nil)
    let task=session.dataTask(with:request){data,response,error in box.data=data;box.response=response;box.error=error;semaphore.signal()};task.resume()
    defer {task.cancel();session.invalidateAndCancel()}
    try require(semaphore.wait(timeout: .now()+timeout) == .success)
    guard box.error==nil,let response=box.response as? HTTPURLResponse,let data=box.data else {throw Refusal.closed}
    try require((200...299).contains(response.statusCode) && data.count<=262144)
    guard let o=try JSONSerialization.jsonObject(with:data) as? [String:Any] else {throw Refusal.closed};return o
}
final class ResponseBox: @unchecked Sendable {var data:Data?;var response:URLResponse?;var error:Error?}
final class NoRedirect:NSObject,URLSessionTaskDelegate {func urlSession(_ session:URLSession,task:URLSessionTask,willPerformHTTPRedirection response:HTTPURLResponse,newRequest request:URLRequest,completionHandler:@escaping(URLRequest?)->Void){completionHandler(nil)}}
let preFields:Set<String>=["schema","phase","context","key","wall_ms","observe_deadline_ms","cleanup_deadline_ms","facts","source","binary","files","authority"]
func prepare() throws {
    defer {cleanupTerminal()}
    try require(getuid()==0 && geteuid()==0 && MemoryLayout<Int>.size==8)
    #if !arch(arm64)
    throw Refusal.closed
    #endif
    let originalWall=wall(),originalMono=try mono(),originalFacts=try nativeFacts()
    cleanupWallDeadline=originalWall+900000;cleanupMonoDeadline=originalMono+900000
    try require(capability_preparation_image()==1)
    let input=try object(FileHandle.standardInput.readData(ofLength:32769),["context","token","source"])
    guard let context=input["context"] as? [String:Any] else {throw Refusal.closed}
    try require(Set(context.keys)==["repository","head","run","attempt","job","nonce"] && (try text(context,"repository"))==repo && matches(try text(context,"head"),"^[0-9a-f]{40}$") && matches(try text(context,"nonce"),"^[0-9a-f]{64}$"))
    for f in ["run","attempt","job"] {try require(number(context,f)>0)}
    let token=try text(input,"token"),source=try text(input,"source");try require(token.count>=20 && token.count<=2048 && !token.contains("\n") && matches(source,"^[0-9a-f]{64}$"))
    var parent=stat();for p in ["/","/Library","/Library/LaunchDaemons"] {try require(lstat(p,&parent)==0 && (parent.st_mode&S_IFMT)==S_IFDIR && parent.st_uid==0 && (parent.st_mode&0o022)==0)}
    try require(mkdir(base,0o700)==0);try require(chmod(base,0o700)==0);var createdBase=stat();try require(lstat(base,&createdBase)==0);baseIdentity=(createdBase.st_dev,createdBase.st_ino)
    // Exact compiled image is measured from the hosted source-selected preparation process.
    let executable="/Library/ZunderGitHubRebootCapabilityBuild/broker"
    try require(CommandLine.arguments[0]==executable)
    var staging=stat();try require(lstat("/Library/ZunderGitHubRebootCapabilityBuild",&staging)==0 && (staging.st_mode&S_IFMT)==S_IFDIR && staging.st_uid==0 && (staging.st_mode&0o7777)==0o700)
    let staged=open(executable,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);try require(staged>=0);defer {close(staged)}
    var image=stat();try require(fstat(staged,&image)==0 && (image.st_mode&S_IFMT)==S_IFREG && image.st_uid==0 && image.st_nlink==1 && (image.st_mode&0o7777)==0o755 && image.st_size>0 && image.st_size<=4194304)
    let length=Int(image.st_size);var data=Data(count:length);try require(data.withUnsafeMutableBytes {read(staged,$0.baseAddress,length)}==length)
    try create(base+"/broker",data,0o755)
    let key=Curve25519.Signing.PrivateKey();let publicKey=key.publicKey.rawRepresentation.base64EncodedString()
    try create(base+"/key",key.rawRepresentation,0o600);try create(base+"/token",Data(token.utf8),0o600)
    let config:[String:Any]=["schema":1,"context":context,"key":publicKey,"source":source,"binary":digest(data),"wall_ms":originalWall,"mono_ms":originalMono,"facts":originalFacts,"directory":["dev":Int64(createdBase.st_dev),"ino":Int64(createdBase.st_ino)]]
    let configData=try encoded(config),configHash=digest(configData);try create(base+"/config",configData,0o600);try create(plistPath,plist(configHash),0o600)
    var files:[String:Any]=[:];for (name,path,mode) in [("binary",base+"/broker",mode_t(0o755)),("config",base+"/config",mode_t(0o600)),("key",base+"/key",mode_t(0o600)),("token",base+"/token",mode_t(0o600)),("plist",plistPath,mode_t(0o600))] {files[name]=try Retained(path,mode).identity}
    let pre:[String:Any]=["schema":1,"phase":"PREBOOT","context":context,"key":publicKey,"wall_ms":originalWall,"observe_deadline_ms":originalWall+720000,"cleanup_deadline_ms":originalWall+900000,"facts":originalFacts,"source":source,"binary":digest(data),"files":files,"authority":deniedAuthority]
    let preEnvelope=try signed(pre,key),bundle:[String:Any]=["schema":1,"phase":"PREBOOT","key":publicKey,"preboot":preEnvelope]
    try require(wall()>=originalWall && wall()-originalWall<60000 && (try mono())-originalMono<60000)
    let external="\(try number(context,"run")):\(try number(context,"attempt")):\(try number(context,"job")):\(try text(context,"nonce"))"
    let response=try api("POST","",token,["name":checkName,"head_sha":try text(context,"head"),"external_id":external,"status":"in_progress","output":["title":checkName,"summary":String(data:try encoded(bundle),encoding:.utf8)!]],5)
    let id=try number(response,"id");try require(id>0 && (try text(response,"head_sha"))==(try text(context,"head")) && (try text(response,"external_id"))==external)
    try createRegistration(id,preEnvelope,key)
    try require(wall()<originalWall+715000 && (try mono())-originalMono<715000)
    try fixedProcess("/bin/launchctl",["bootstrap","system",plistPath]);bootstrapSucceeded=true
    try require(wall()>=originalWall && wall()<originalWall+715000 && (try mono())-originalMono<715000)
    // This probe has no observer ACK and grants no release authority.
    try fixedProcess("/sbin/shutdown",["-r","now"])
    // Keep the original target job alive if shutdown returns; never issue a second reboot.
    while wall()>=originalWall && wall()<originalWall+890000 && (try mono())-originalMono<890000 {sleep(1)}
}
func watch(_ configHash:String) throws {
    try require(getuid()==0 && geteuid()==0 && capability_watch_image()==1 && matches(configHash,"^[0-9a-f]{64}$"))
    let configFile=try Retained(base+"/config",0o600);try require(digest(configFile.data)==configHash)
    let c=try object(configFile.data,["schema","context","key","source","binary","wall_ms","mono_ms","facts","directory"])
    guard let directory=c["directory"] as? [String:Any] else {throw Refusal.closed}
    try require(Set(directory.keys)==["dev","ino"]);var baseInfo=stat();try require(lstat(base,&baseInfo)==0 && Int64(baseInfo.st_dev)==number(directory,"dev") && Int64(baseInfo.st_ino)==number(directory,"ino"));baseIdentity=(baseInfo.st_dev,baseInfo.st_ino)
    let keyFile=try Retained(base+"/key",0o600),key=try Curve25519.Signing.PrivateKey(rawRepresentation:keyFile.data);try require(key.publicKey.rawRepresentation.base64EncodedString()==text(c,"key"))
    let registrationFile=try Retained(base+"/registration",0o600),r=try verified(try object(registrationFile.data,["payload","signature"]),key.publicKey,["schema","id","preboot","identity"])
    guard let registeredIdentity=r["identity"] as? [String:Any] else {throw Refusal.closed}
    try require(Set(registeredIdentity.keys)==["dev","ino","mode"] && number(registeredIdentity,"dev")==Int64(registrationFile.info.st_dev) && number(registeredIdentity,"ino")==Int64(registrationFile.info.st_ino) && number(registeredIdentity,"mode")==384 && number(r,"schema")==1)
    guard let preEnvelope=r["preboot"] as? [String:Any] else {throw Refusal.closed}
    let pre=try verified(preEnvelope,key.publicKey,preFields)
    try require(encoded(pre["authority"]!)==encoded(deniedAuthority))
    try require(number(pre,"schema")==1 && text(pre,"phase")=="PREBOOT" && text(pre,"key")==text(c,"key") && encoded(pre["context"]!)==encoded(c["context"]!) && text(pre,"source")==text(c,"source") && text(pre,"binary")==text(c,"binary") && number(pre,"wall_ms")==number(c,"wall_ms") && number(pre,"observe_deadline_ms")==number(c,"wall_ms")+720000 && number(pre,"cleanup_deadline_ms")==number(c,"wall_ms")+900000)
    guard let expected=pre["files"] as? [String:Any],let before=pre["facts"] as? [String:Any] else {throw Refusal.closed}
    var retained:[String:Retained]=[:]
    for (name,path,mode) in [("binary",base+"/broker",mode_t(0o755)),("config",base+"/config",mode_t(0o600)),("key",base+"/key",mode_t(0o600)),("token",base+"/token",mode_t(0o600)),("plist",plistPath,mode_t(0o600))] {let f=try Retained(path,mode);guard let e=expected[name] as? [String:Any] else {throw Refusal.closed};try require(encoded(f.identity)==encoded(e));retained[name]=f}
    try require(retained["plist"]!.data==plist(configHash) && digest(retained["binary"]!.data)==text(c,"binary"))
    // Only authenticated retained resources may be cleaned on a terminal failure.
    terminalFiles=retained;terminalFiles["registration"]=registrationFile
    defer {cleanupTerminal()}
    let origin=try number(pre,"wall_ms"),originMono=try number(c,"mono_ms"),boot=try bootText()
    cleanupWallDeadline=origin+900000
    if boot==(try text(before,"boot")) {
        cleanupMonoDeadline=originMono+900000
        var lastWall=wall(),lastMono=try mono()
        while lastWall>=origin && lastWall<origin+890000 && lastMono>=originMono && lastMono-originMono<890000 {sleep(1);let w=wall(),m=try mono();if w<lastWall || m<lastMono {break};lastWall=w;lastMono=m}
        for name in ["token","key","binary","config","plist"] {_ = retained[name]!.remove()};_ = registrationFile.remove()
        try? fixedProcess("/bin/launchctl",["bootout","system/"+label]);return
    }
    let reportingStart=try mono(),observedWall=wall();try require(observedWall>=origin && observedWall<origin+720000)
    let after=try nativeFacts();try require(text(after,"machine")==text(before,"machine") && number(after,"boot_ms")>number(before,"boot_ms") && number(after,"birth_ms")>number(before,"birth_ms") && number(after,"uptime_ms")<=120000)
    let token=String(data:retained["token"]!.data,encoding:.utf8)!;let id=try number(r,"id");try require(id>0)
    // Consume live registration once before any postboot mutation or network update.
    try require(registrationFile.remove()=="ABSENT_OBSERVED")
    var cleanup:[String:Any]=["registration":"ABSENT_OBSERVED","service":"UNKNOWN","self_exit":"UNKNOWN","vm":"UNKNOWN"]
    for name in ["token","key","binary","config","plist"] {cleanup[name]=retained[name]!.remove()}
    let now=wall(),age=(try mono())-reportingStart;try require(now>=observedWall && now<origin+720000 && age>=0 && age<5000)
    let post:[String:Any]=["schema":1,"phase":"POSTBOOT","context":pre["context"]!,"key":pre["key"]!,"wall_ms":now,"facts":after,"source":pre["source"]!,"binary":pre["binary"]!,"preboot_sha":digest(try encoded(preEnvelope)),"cleanup":cleanup,"authority":deniedAuthority]
    let body:[String:Any]=["schema":1,"phase":"POSTBOOT","key":pre["key"]!,"preboot":preEnvelope,"postboot":try signed(post,key)]
    _ = try? api("PATCH","/\(id)",token,["status":"completed","conclusion":"neutral","output":["title":checkName,"summary":String(data:try encoded(body),encoding:.utf8)!]],min(5-Double(age)/1000,Double(origin+720000-now)/1000))
    try? fixedProcess("/bin/launchctl",["bootout","system/"+label])
}
do {
    umask(0o077)
    if CommandLine.arguments==[CommandLine.arguments[0],"prepare"] {try prepare()}
    else if CommandLine.arguments.count==3 && CommandLine.arguments[1]=="watch" {try watch(CommandLine.arguments[2])}
    else {throw Refusal.closed}
} catch {exit(1)}
