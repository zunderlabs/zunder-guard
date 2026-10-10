// Standalone no-key native Windows facts and scratch resources. No Guard, signing, provider or reboot.
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using Microsoft.Win32.SafeHandles;

internal static class PhaseZero {
  const string Root = @"C:\ProgramData\ZunderPublicWindowsPhaseZero";
  const string Exe = Root + @"\phase-zero.exe";
  const string Marker = Root + @"\marker.bin";
  const string ServiceName = "ZunderPublicWindowsPhaseZero";
  const string Account = @"NT SERVICE\ZunderPublicWindowsPhaseZero";
  const string JobName = @"Global\ZunderPublicWindowsPhaseZeroJob";
  const string ImagePath = "\"" + Exe + "\" --service";
  const int Port = 18547;
  const int LimitMs = 120000;
  const uint FileAll = 0x001f01ff, FileReadExecute = 0x001200a9;
  const uint CREATE_SUSPENDED = 4, DETACHED_PROCESS = 8, CREATE_UNICODE_ENVIRONMENT = 0x400;
  static readonly byte[] MarkerBytes = Encoding.ASCII.GetBytes("zunder-no-key-native-phase-zero-v1\n");
  static readonly ManualResetEvent ServiceStop = new ManualResetEvent(false);
  static N.ServiceMain MainDelegate = ServiceMain;
  static N.Handler HandlerDelegate = ServiceControl;
  static IntPtr StatusHandle;
  static uint ServiceCheckpoint = 1; // Finite self-reported diagnostics only, never ownership evidence.
  static string stage = "preflight";
  static Dictionary<string, object> report;

  static Dictionary<string, object> D(params object[] pairs) {
    var d = new Dictionary<string, object>();
    for (int i = 0; i < pairs.Length; i += 2) d.Add((string)pairs[i], pairs[i + 1]);
    return d;
  }
  sealed class Refused : Exception {
    internal readonly string Class; internal readonly uint Code;
    internal Refused(string c, uint n) { Class = c; Code = n; }
  }
  static void Need(bool yes, string c) { if (!yes) throw new Refused(c, 0); }
  static void Win(bool yes, string c) { if (!yes) throw new Refused(c, unchecked((uint)Marshal.GetLastWin32Error())); }
  sealed class H : IDisposable {
    internal IntPtr P; readonly bool service;
    internal H(IntPtr p, bool sc) { Win(p != IntPtr.Zero && p != new IntPtr(-1), "handle"); P = p; service = sc; }
    public void Dispose() { if (P != IntPtr.Zero) { if (service) N.CloseServiceHandle(P); else N.CloseHandle(P); P = IntPtr.Zero; } }
  }
  sealed class SD : IDisposable {
    internal IntPtr P;
    internal SD(string value) { Win(N.ConvertStringSecurityDescriptorToSecurityDescriptorW(value, 1, out P, IntPtr.Zero), "security"); }
    internal N.SECURITY_ATTRIBUTES Attributes() { return new N.SECURITY_ATTRIBUTES { Length = Marshal.SizeOf(typeof(N.SECURITY_ATTRIBUTES)), Descriptor = P, Inherit = 0 }; }
    public void Dispose() { if (P != IntPtr.Zero) { N.LocalFree(P); P = IntPtr.Zero; } }
  }
  static string Sha(byte[] b) { using (var a = new SHA256Managed()) return Hex(a.ComputeHash(b)); }
  static string Hex(byte[] b) { var s = new StringBuilder(); foreach (byte x in b) s.Append(x.ToString("x2")); return s.ToString(); }
  static string SID(IntPtr p) { IntPtr text; Win(N.IsValidSid(p), "security"); Win(N.ConvertSidToStringSidW(p, out text), "security"); try { return Marshal.PtrToStringUni(text); } finally { N.LocalFree(text); } }
  static string ServiceSID() {
    uint bytes = 0, chars = 0; int use;
    N.LookupAccountNameW(null, Account, null, ref bytes, null, ref chars, out use);
    Need(Marshal.GetLastWin32Error() == 122 && bytes > 0 && bytes <= 128 && chars <= 512, "security");
    var sid = new byte[bytes]; var domain = new StringBuilder((int)chars);
    Win(N.LookupAccountNameW(null, Account, sid, ref bytes, domain, ref chars, out use), "security");
    var pin = GCHandle.Alloc(sid, GCHandleType.Pinned);
    try { string s = SID(pin.AddrOfPinnedObject()); Need(s.StartsWith("S-1-5-80-", StringComparison.Ordinal) && s.Length <= 128, "security"); return s; } finally { pin.Free(); }
  }
  static string TokenSID(IntPtr process) {
    IntPtr raw; Win(N.OpenProcessToken(process, 8, out raw), "process");
    using (var token = new H(raw, false)) {
      uint size = 0; N.GetTokenInformation(token.P, 1, IntPtr.Zero, 0, out size);
      Need(Marshal.GetLastWin32Error() == 122 && size >= 16 && size <= 512, "process");
      IntPtr b = Marshal.AllocHGlobal((int)size);
      try { Win(N.GetTokenInformation(token.P, 1, b, size, out size), "process"); return SID(Marshal.ReadIntPtr(b)); } finally { Marshal.FreeHGlobal(b); }
    }
  }
  static ulong FT(N.FILETIME x) { return ((ulong)x.High << 32) | x.Low; }
  static ulong Clock() { N.FILETIME f; N.GetSystemTimePreciseAsFileTime(out f); return FT(f); }
  static string Tick(ulong x) { return x.ToString(System.Globalization.CultureInfo.InvariantCulture); }
  static uint FailedJobMembers(H job, uint childPid, uint servicePid) {
    IntPtr buffer = Marshal.AllocHGlobal(72);
    try {
      uint returned; Win(N.QueryJobProcessIds(job.P, 3, buffer, 72, out returned), "job");
      uint assigned = unchecked((uint)Marshal.ReadInt32(buffer, 0)); uint count = unchecked((uint)Marshal.ReadInt32(buffer, 4));
      Need(count >= 1 && count <= 8 && assigned == count && returned >= 8U + count * 8U && returned <= 72, "job");
      var seen = new Dictionary<uint, bool>(); uint mask = 0;
      for (uint i = 0; i < count; i++) {
        ulong raw = unchecked((ulong)Marshal.ReadInt64(buffer, checked(8 + (int)i * 8)));
        Need(raw > 0 && raw <= uint.MaxValue, "job"); uint pid = (uint)raw;
        Need(!seen.ContainsKey(pid), "job"); seen.Add(pid, true);
        if (pid == childPid) mask |= 1U;
        else if (pid == servicePid) mask |= 2U;
        else if (pid == N.GetCurrentProcessId()) mask |= 4U;
        else {
          using (var process = new H(N.OpenProcess(0x1000, false, pid), false)) {
            var image = new StringBuilder(32768); uint size = 32768;
            Win(N.QueryFullProcessImageNameW(process.P, 0, image, ref size), "job");
            Need(size > 0 && size < 32768, "job");
            mask |= String.Equals(image.ToString(), @"C:\Windows\System32\conhost.exe", StringComparison.OrdinalIgnoreCase) ? 8U : 16U;
          }
        }
      }
      return 0x4d420000U | mask;
    } finally { Marshal.FreeHGlobal(buffer); }
  }
  static Dictionary<string, object> Boot() {
    Need(Marshal.SizeOf(typeof(N.BOOT_ENV)) == 32 && Marshal.SizeOf(typeof(N.TIME_OF_DAY)) == 48 && Marshal.SizeOf(typeof(N.BASIC_PROCESS)) == 48, "abi");
    foreach (string dll in new string[] { "ntdll.dll", "kernel32.dll", "advapi32.dll", "iphlpapi.dll", "shell32.dll" }) {
      IntPtr module = N.GetModuleHandleW(dll); // Bind these fixed KnownDLL imports to the actual OS image path.
      if (module == IntPtr.Zero) module = N.LoadLibraryExW(@"C:\Windows\System32\" + dll, IntPtr.Zero, 0x800);
      Win(module != IntPtr.Zero, "abi"); var path = new StringBuilder(1024);
      Win(N.GetModuleFileNameW(module, path, path.Capacity) > 0, "abi");
      Need(String.Equals(path.ToString(), @"C:\Windows\System32\" + dll, StringComparison.OrdinalIgnoreCase), "abi");
    }
    ulong before = Clock(); long qb = 0, qa = 0, freq = 0; Win(N.QueryPerformanceCounter(out qb) && N.QueryPerformanceFrequency(out freq), "clock");
    uint length; var boot = new N.BOOT_ENV(); var tod = new N.TIME_OF_DAY();
    int a = N.NtQueryBoot(90, ref boot, 32, out length); if (a != 0 || length != 32) throw new Refused("boot_environment", unchecked((uint)a));
    a = N.NtQueryTime(3, ref tod, 48, out length); if (a != 0 || length != 48) throw new Refused("time_of_day", unchecked((uint)a));
    // Current UTC is one documented precise sample, not the opaque TOD snapshot.
    ulong current = Clock();
    ulong uptime = N.GetTickCount64(); Win(N.QueryPerformanceCounter(out qa), "clock"); ulong after = Clock();
    // Fixed source-owned Boot guard IDs, not Win32 errors; original short-circuit order.
    if (!(before <= after)) throw new Refused("clock_guard", 1);
    if (!(qb >= 0)) throw new Refused("clock_guard", 2);
    if (!(qa >= qb)) throw new Refused("clock_guard", 3);
    if (!(freq > 0)) throw new Refused("clock_guard", 4);
    if (!(boot.Id != Guid.Empty)) throw new Refused("clock_guard", 5);
    if (!(tod.BootTime > 0)) throw new Refused("clock_guard", 6);
    if (!(tod.CurrentTime > 0 && tod.CurrentTime >= tod.BootTime)) throw new Refused("clock_guard", 7);
    if (!(unchecked((ulong)tod.BootTime) <= before)) throw new Refused("clock_guard", 8);
    if (!(current >= before)) throw new Refused("clock_guard", 9);
    if (!(current <= after)) throw new Refused("clock_guard", 10);
    if (!(after - before <= 50000000)) throw new Refused("clock_guard", 11);
    return D("state", "OBSERVED", "guid", boot.Id.ToString("D"), "boot_filetime", Tick(unchecked((ulong)tod.BootTime)),
      "current_filetime", Tick(current), "observation_before_filetime", Tick(before),
      "observation_after_filetime", Tick(after), "qpc_before", Tick((ulong)qb), "qpc_after", Tick((ulong)qa),
      "qpc_frequency", Tick((ulong)freq), "uptime_ms", Tick(uptime));
  }
  static Dictionary<string, object> ProcessFacts(H p, uint pid, string expectedSID, string digest) {
    ulong before = Clock(); N.FILETIME birth, exit, kernel, user;
    Win(N.GetProcessTimes(p.P, out birth, out exit, out kernel, out user), "process");
    var basic = new N.BASIC_PROCESS(); uint returned;
    Need(N.NtQueryInformationProcess(p.P, 0, ref basic, 48, out returned) == 0 && returned == 48 && basic.Pid.ToUInt64() == pid &&
      basic.Parent.ToUInt64() > 0 && basic.Parent.ToUInt64() <= uint.MaxValue, "process");
    var path = new StringBuilder(1024); uint size = 1024;
    Win(N.QueryFullProcessImageNameW(p.P, 0, path, ref size), "process");
    Need(String.Equals(path.ToString(), Exe, StringComparison.OrdinalIgnoreCase), "ownership");
    string sid = TokenSID(p.P); Need(sid == expectedSID, "ownership"); ulong after = Clock();
    Need(before <= after && FT(birth) > 0 && FT(birth) <= after, "clock");
    return D("pid", pid, "creation_filetime", Tick(FT(birth)), "parent_pid", (uint)basic.Parent.ToUInt64(),
      "image_sha256", digest, "fixed_image_match", true, "virtual_sid_match", true,
      "observation_before_filetime", Tick(before), "observation_after_filetime", Tick(after));
  }
  static H OpenFile(string path, bool directory, bool remove) {
    H h = new H(N.CreateFileW(path, 0x80020000U | (remove ? 0x10000U : 0), 1, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero), false);
    try {
      N.BY_HANDLE info; Win(N.GetFileInformationByHandle(h.P, out info), "file");
      Need((info.Attributes & 0x400) == 0 && ((info.Attributes & 0x10) != 0) == directory && (directory || info.Links == 1), "ownership");
      var final = new StringBuilder(1024); uint count = N.GetFinalPathNameByHandleW(h.P, final, (uint)final.Capacity, 0);
      Need(count > 0 && count < final.Capacity && String.Equals(final.ToString(), @"\\?\" + path, StringComparison.OrdinalIgnoreCase), "ownership");
      return h;
    } catch { h.Dispose(); throw; }
  }
  static void ExecutablePath(H h) {
    N.BY_HANDLE info; Win(N.GetFileInformationByHandle(h.P, out info), "file");
    Need((info.Attributes & 0x410) == 0 && info.Links == 1, "ownership");
    var final = new StringBuilder(1024); uint count = N.GetFinalPathNameByHandleW(h.P, final, (uint)final.Capacity, 0);
    Need(count > 0 && count < final.Capacity && String.Equals(final.ToString(), @"\\?\" + Exe, StringComparison.OrdinalIgnoreCase), "ownership");
  }
  static H OpenExecutableRead() {
    // Fixed image only: no requested DELETE/WRITE; permit a CLR READ-only opener.
    // READ|DELETE sharing still denies writes. Later deletion must rejoin identity.
    var h = new H(N.CreateFileW(Exe, 0x80020000U, 5, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero), false);
    try { ExecutablePath(h); return h; } catch { h.Dispose(); throw; }
  }
  static void SameExecutable(Dictionary<string, object> original, Dictionary<string, object> current) {
    Need((string)original["file_id"] == (string)current["file_id"] &&
      (string)original["volume_serial"] == (string)current["volume_serial"], "ownership");
  }
  static bool DeleteExecutableHandle(H retained, string sid, string expectedDigest) {
    Need(expectedDigest != null && expectedDigest.Length == 64, "ownership");
    ExecutablePath(retained); var original = FileFacts(retained, false, sid);
    Need(FileDigest(retained) == expectedDigest, "ownership");
    // Captured processes are terminal before this call. Keep original READ
    // handle open while exact-path deletion handle is checked; never adopt it.
    using (var removal = OpenFile(Exe, false, true)) {
      ExecutablePath(removal); var current = FileFacts(removal, false, sid);
      SameExecutable(original, current); Need(FileDigest(removal) == expectedDigest, "ownership");
      ExecutablePath(retained); ExecutablePath(removal);
      SameExecutable(original, FileFacts(retained, false, sid));
      SameExecutable(original, FileFacts(removal, false, sid));
      Need(FileDigest(retained) == expectedDigest && FileDigest(removal) == expectedDigest, "ownership");
      var disposition = new N.DISPOSITION { Delete = 1 };
      if (!N.SetFileInformationByHandle(removal.P, 4, ref disposition, 1)) return false;
      retained.Dispose(); removal.Dispose(); return MissingPath(Exe);
    }
  }
  static Dictionary<string, object> FileFacts(H h, bool directory, string sid) {
    N.BY_HANDLE basic; var id = new N.FILE_ID_INFO { Id = new byte[16] };
    Win(N.GetFileInformationByHandle(h.P, out basic) && N.GetFileInformationByHandleEx(h.P, 18, ref id, 24), "file");
    Need(id.Id != null && id.Id.Length == 16 && (basic.Attributes & 0x400) == 0 && (directory || basic.Links == 1), "ownership");
    IntPtr owner, group, dacl, sacl, descriptor;
    Need(N.GetSecurityInfo(h.P, 1, 5, out owner, out group, out dacl, out sacl, out descriptor) == 0, "security");
    try {
      ushort control; uint revision;
      Win(N.GetSecurityDescriptorControl(descriptor, out control, out revision), "security");
      Need(SID(owner) == "S-1-5-32-544" && (control & 0x1000) != 0 && dacl != IntPtr.Zero, "ownership");
      N.ACL_SIZE acl; Win(N.GetAclInformation(dacl, out acl, (uint)Marshal.SizeOf(typeof(N.ACL_SIZE)), 2), "security");
      Need(acl.Count == 3, "ownership"); var seen = new Dictionary<string, bool>();
      for (uint n = 0; n < acl.Count; n++) {
        IntPtr ace; Win(N.GetAce(dacl, n, out ace), "security");
        Need(Marshal.ReadByte(ace) == 0 && Marshal.ReadByte(ace, 1) == 0 && (ushort)Marshal.ReadInt16(ace, 2) >= 12, "ownership");
        uint mask = unchecked((uint)Marshal.ReadInt32(ace, 4)); string a = SID(IntPtr.Add(ace, 8));
        Need(!seen.ContainsKey(a) && (a == "S-1-5-18" || a == "S-1-5-32-544" ? mask == FileAll : a == sid && mask == FileReadExecute), "ownership"); seen.Add(a, true);
      }
      return D("file_id", Hex(id.Id), "volume_serial", Tick(id.Volume), "links", basic.Links,
        "reparse", false, "protected_dacl_match", true, "owner_class", "ADMINISTRATORS", "sha256", null);
    } finally { N.LocalFree(descriptor); }
  }
  static void JobSecurity(H job, string sid) {
    IntPtr owner, group, dacl, sacl, descriptor;
    Need(N.GetSecurityInfo(job.P, 6, 5, out owner, out group, out dacl, out sacl, out descriptor) == 0, "security");
    try {
      ushort control; uint revision; Win(N.GetSecurityDescriptorControl(descriptor, out control, out revision), "security");
      if (!(SID(owner) == sid)) throw new Refused("ownership", 0x4a4f4201);
      if (!((control & 0x1000) != 0)) throw new Refused("ownership", 0x4a4f4202);
      if (!(dacl != IntPtr.Zero)) throw new Refused("ownership", 0x4a4f4203);
      N.ACL_SIZE acl; Win(N.GetAclInformation(dacl, out acl, (uint)Marshal.SizeOf(typeof(N.ACL_SIZE)), 2), "security");
      if (!(acl.Count == 3)) throw new Refused("ownership", 0x4a4f4204); var seen = new Dictionary<string, bool>();
      for (uint n = 0; n < 3; n++) {
        IntPtr ace; Win(N.GetAce(dacl, n, out ace), "security");
        if (!(Marshal.ReadByte(ace) == 0)) throw new Refused("ownership", 0x4a4f4205);
        if (!(Marshal.ReadByte(ace, 1) == 0)) throw new Refused("ownership", 0x4a4f4206);
        if (!((ushort)Marshal.ReadInt16(ace, 2) >= 12)) throw new Refused("ownership", 0x4a4f4207);
        string a = SID(IntPtr.Add(ace, 8)); uint mask = unchecked((uint)Marshal.ReadInt32(ace, 4));
        if (!(!seen.ContainsKey(a))) throw new Refused("ownership", 0x4a4f4208);
        if (!(mask == 0x1f003f)) throw new Refused("ownership", 0x4a4f4209);
        if (!((a == sid || a == "S-1-5-18" || a == "S-1-5-32-544"))) throw new Refused("ownership", 0x4a4f420a); seen.Add(a, true);
      }
    } finally { N.LocalFree(descriptor); }
  }
  static string FileDigest(H h) {
    using (var stream = new FileStream(new SafeFileHandle(h.P, false), FileAccess.Read)) {
      Need(stream.Length > 0 && stream.Length <= 16777216, "file"); stream.Position = 0;
      using (var sha = new SHA256Managed()) return Hex(sha.ComputeHash(stream));
    }
  }
  static H NewFile(string path, byte[] data, SD sd) {
    N.SECURITY_ATTRIBUTES sa = sd.Attributes();
    H h = new H(N.CreateFileNewW(path, 0xc0030000, 1, ref sa, 1, 0x00200000, IntPtr.Zero), false);
    try {
      uint written; Win(N.WriteFile(h.P, data, (uint)data.Length, out written, IntPtr.Zero) && written == data.Length && N.FlushFileBuffers(h.P), "file");
      var captured = new N.FILE_ID_INFO { Id = new byte[16] };
      Win(N.GetFileInformationByHandleEx(h.P, 18, ref captured, 24), "file");
      h.Dispose(); // An open write handle cannot be carried into image-section creation.
      var read = path == Exe ? OpenExecutableRead() : OpenFile(path, false, true);
      try {
        var again = new N.FILE_ID_INFO { Id = new byte[16] };
        Win(N.GetFileInformationByHandleEx(read.P, 18, ref again, 24), "file");
        Need(captured.Volume == again.Volume && Hex(captured.Id) == Hex(again.Id), "ownership"); return read;
      } catch { read.Dispose(); throw; }
    } catch {
      if (h.P != IntPtr.Zero) { var remove = new N.DISPOSITION { Delete = 1 }; N.SetFileInformationByHandle(h.P, 4, ref remove, 1); }
      h.Dispose(); throw;
    }
  }
  static bool MissingPath(string path) {
    uint a = N.GetFileAttributesW(path); int error = Marshal.GetLastWin32Error();
    return a == uint.MaxValue && (error == 2 || error == 3);
  }
  static bool DeleteFileHandle(H h, string path) {
    var info = new N.DISPOSITION { Delete = 1 };
    if (!N.SetFileInformationByHandle(h.P, 4, ref info, 1)) return false;
    h.Dispose(); return MissingPath(path);
  }
  static bool ServiceMissing(H scm) {
    IntPtr x = N.OpenServiceW(scm.P, ServiceName, 4); int e = Marshal.GetLastWin32Error();
    if (x != IntPtr.Zero) { N.CloseServiceHandle(x); return false; } return e == 1060;
  }
  static void ObserveStartupStatus(H service) {
    N.SERVICE_STATUS_PROCESS actual; uint bytes;
    if (!N.QueryServiceStatusEx(service.P, 0, out actual, (uint)Marshal.SizeOf(typeof(N.SERVICE_STATUS_PROCESS)), out bytes) ||
        bytes != Marshal.SizeOf(typeof(N.SERVICE_STATUS_PROCESS)) || actual.State < 1 || actual.State > 7) return;
    report["startup_status"] = D("state", "OBSERVED", "service_state", actual.State, "win32_exit", actual.Win32Exit, "service_exit", actual.ServiceExit);
  }
  static uint ServiceState(H service) {
    N.SERVICE_STATUS_PROCESS s; uint bytes;
    Win(N.QueryServiceStatusEx(service.P, 0, out s, (uint)Marshal.SizeOf(typeof(N.SERVICE_STATUS_PROCESS)), out bytes), "scm");
    return s.State;
  }
  static uint ServicePid(H service) {
    N.SERVICE_STATUS_PROCESS s; uint bytes;
    Win(N.QueryServiceStatusEx(service.P, 0, out s, (uint)Marshal.SizeOf(typeof(N.SERVICE_STATUS_PROCESS)), out bytes), "scm");
    Need(s.State == 4 && s.Pid > 0, "scm"); return s.Pid;
  }
  static void BasicConfigMatch(H service) {
    uint bytes = 0; N.QueryServiceConfigW(service.P, IntPtr.Zero, 0, out bytes);
    Need(Marshal.GetLastWin32Error() == 122 && bytes > 0 && bytes <= 8192, "scm");
    IntPtr b = Marshal.AllocHGlobal((int)bytes);
    try {
      Win(N.QueryServiceConfigW(service.P, b, bytes, out bytes), "scm"); var c = (N.SERVICE_CONFIG)Marshal.PtrToStructure(b, typeof(N.SERVICE_CONFIG));
      Need(c.Type == 0x10 && c.Start == 3 && c.Error == 1 && Marshal.PtrToStringUni(c.Binary) == ImagePath &&
        String.Equals(Marshal.PtrToStringUni(c.Account), Account, StringComparison.OrdinalIgnoreCase) &&
        (c.Dependencies == IntPtr.Zero || Marshal.ReadInt16(c.Dependencies) == 0), "ownership");
    } finally { Marshal.FreeHGlobal(b); }
  }
  static void ConfigMatch(H service) {
    BasicConfigMatch(service); uint bytes; IntPtr b = Marshal.AllocHGlobal(8192);
    try {
      Win(N.QueryServiceConfig2W(service.P, 2, b, 8192, out bytes), "scm");
      var f = (N.FAILURE_ACTIONS)Marshal.PtrToStructure(b, typeof(N.FAILURE_ACTIONS));
      Need(f.Count == 0 && f.Reset == 0 && (f.Command == IntPtr.Zero || Marshal.ReadInt16(f.Command) == 0) &&
        (f.Reboot == IntPtr.Zero || Marshal.ReadInt16(f.Reboot) == 0), "ownership");
      Win(N.QueryServiceConfig2W(service.P, 4, b, 8192, out bytes), "scm"); Need(Marshal.ReadInt32(b) == 0, "ownership");
      Win(N.QueryServiceConfig2W(service.P, 5, b, 8192, out bytes), "scm"); Need(Marshal.ReadInt32(b) == 1, "ownership");
    } finally { Marshal.FreeHGlobal(b); }
  }
  static List<uint> ListenerPids() {
    uint bytes = 0; uint result = N.GetExtendedTcpTable(IntPtr.Zero, ref bytes, false, 2, 3, 0);
    Need((result == 122 || result == 0) && bytes >= 4 && bytes <= 4194304, "listener");
    IntPtr b = Marshal.AllocHGlobal((int)bytes);
    try {
      Need(N.GetExtendedTcpTable(b, ref bytes, false, 2, 3, 0) == 0, "listener"); uint count = unchecked((uint)Marshal.ReadInt32(b));
      Need(count <= 65536 && (ulong)count * 24 + 4 <= bytes, "listener"); var pids = new List<uint>();
      for (uint i = 0; i < count; i++) {
        IntPtr row = IntPtr.Add(b, checked(4 + (int)i * 24)); uint state = unchecked((uint)Marshal.ReadInt32(row));
        uint address = unchecked((uint)Marshal.ReadInt32(row, 4)); uint port = unchecked((uint)Marshal.ReadInt32(row, 8));
        int decoded = (int)(((port & 255) << 8) | ((port >> 8) & 255));
        if (state == 2 && decoded == Port) { Need(address == 0x0100007f, "ownership"); pids.Add(unchecked((uint)Marshal.ReadInt32(row, 20))); }
      }
      return pids;
    } finally { Marshal.FreeHGlobal(b); }
  }
  static void Poll(Func<bool> predicate, int bound, string c) {
    ulong start = N.GetTickCount64(); do { if (predicate()) return; Thread.Sleep(50); } while (N.GetTickCount64() - start < (ulong)bound);
    throw new Refused(c, 0);
  }
  static bool RefusedConnect() {
    using (var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp)) {
      socket.Blocking = false;
      try { socket.Connect(IPAddress.Loopback, Port); return false; }
      catch (SocketException e) {
        if (e.SocketErrorCode == SocketError.ConnectionRefused) return true;
        if (e.SocketErrorCode != SocketError.WouldBlock && e.SocketErrorCode != SocketError.InProgress) return false;
        return socket.Poll(1000000, SelectMode.SelectWrite) && (int)socket.GetSocketOption(SocketOptionLevel.Socket, SocketOptionName.Error) == (int)SocketError.ConnectionRefused;
      }
    }
  }
  static Dictionary<string, object> EmptyBoot() { return D("state", "UNKNOWN", "guid", null, "boot_filetime", null, "current_filetime", null,
    "observation_before_filetime", null, "observation_after_filetime", null, "qpc_before", null, "qpc_after", null, "qpc_frequency", null, "uptime_ms", null); }
  static int Probe() {
    report = D("schema", 2, "kind", "WINDOWS_NO_KEY_NATIVE_PHASE_ZERO", "outcome", "UNKNOWN", "stage", "preflight", "error_class", "none", "error_code", 0,
      "actual_native_getter_executed", true, "source_admitted", false, "runtime_admitted", false, "release_ready", false,
      "production_windows_service_acceptance", false, "native_credential_retention_proven", false, "same_host_reboot_proven", false,
      "all_owned_processes_gone", false, "self_exit", "UNKNOWN", "vm_removal", "UNKNOWN", "receipt_memory_absence", "NOT_EXERCISED",
      "boot", EmptyBoot(), "processes", new List<object>(), "files", new List<object>(),
      "startup_status", D("state", "UNKNOWN", "service_state", null, "win32_exit", null, "service_exit", null),
      "scm", D("state", "UNKNOWN", "fixed_config_match", false, "sid_sha256", null, "pid", null),
      "job", D("state", "UNKNOWN", "kill_on_close", false, "child_member", false, "protected_dacl_match", false, "active_processes", null),
      "listener", D("state", "UNKNOWN", "family", "IPv4", "address_class", "LOOPBACK", "port", Port, "owned_pid", null),
      "cleanup", D("scm", "NOT_CREATED", "processes", "NOT_CREATED", "listener", "NOT_CREATED", "files", "NOT_CREATED", "root", "NOT_CREATED"));
    H scm = null, service = null, parent = null, root = null, exe = null, marker = null, serviceProcess = null, child = null;
    bool createdRoot = false, createdService = false, serviceConfigured = false, startedService = false, listenerObserved = false; string sid = null, executableDigest = null; bool complete = false;
    var cleanup = (Dictionary<string, object>)report["cleanup"];
    try {
      Need(IntPtr.Size == 8 && N.IsUserAnAdmin(), "privilege"); report["boot"] = Boot();
      Need(MissingPath(Root), "preexisting"); scm = new H(N.OpenSCManagerW(null, null, 3), true); Need(ServiceMissing(scm), "preexisting");
      Need(ListenerPids().Count == 0, "preexisting");
      IntPtr priorJob = N.OpenJobObjectW(4, false, JobName); int priorError = Marshal.GetLastWin32Error();
      if (priorJob != IntPtr.Zero) { N.CloseHandle(priorJob); throw new Refused("preexisting", 0); } Need(priorError == 2, "preexisting");
      parent = OpenFile(@"C:\ProgramData", true, false);
      stage = "scm"; service = new H(N.CreateServiceW(scm.P, ServiceName, ServiceName, 0x000f01ff, 0x10, 3, 1, ImagePath,
        null, IntPtr.Zero, null, Account, null), true); createdService = true; cleanup["scm"] = "UNKNOWN";
      var serviceSid = new N.SERVICE_SID { Type = 1 }; Win(N.ChangeServiceSid(service.P, 5, ref serviceSid), "scm");
      var flags = new N.FAILURE_FLAG { Enabled = 0 }; Win(N.ChangeServiceFailureFlag(service.P, 4, ref flags), "scm");
      var failure = new N.FAILURE_ACTIONS(); Win(N.ChangeServiceFailure(service.P, 2, ref failure), "scm"); sid = ServiceSID(); ConfigMatch(service); serviceConfigured = true;
      stage = "files";
      using (var sd = new SD("O:BAG:BAD:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;0x1200a9;;;" + sid + ")")) {
        N.SECURITY_ATTRIBUTES sa = sd.Attributes(); Win(N.CreateDirectoryW(Root, ref sa), "file"); createdRoot = true;
        cleanup["root"] = "UNKNOWN"; cleanup["files"] = "UNKNOWN"; root = OpenFile(Root, true, true);
        string self = Assembly.GetExecutingAssembly().Location; byte[] own;
        using (var input = OpenFile(self, false, false)) {
          using (var s = new FileStream(new SafeFileHandle(input.P, false), FileAccess.Read)) {
            Need(s.Length > 0 && s.Length <= 16777216, "file"); own = new byte[checked((int)s.Length)];
            int got = 0; while (got < own.Length) { int n = s.Read(own, got, own.Length - got); Need(n > 0, "file"); got += n; }
          }
        }
        exe = NewFile(Exe, own, sd); marker = NewFile(Marker, MarkerBytes, sd);
      }
      var files = (List<object>)report["files"];
      var rf = FileFacts(root, true, sid); rf["role"] = "root"; files.Add(rf);
      var ef = FileFacts(exe, false, sid); ef["role"] = "executable"; files.Add(ef);
      var mf = FileFacts(marker, false, sid); mf["role"] = "marker"; files.Add(mf);
      string digest = FileDigest(exe); executableDigest = digest; ef["sha256"] = digest; mf["sha256"] = FileDigest(marker); rf["sha256"] = null;
      stage = "startup"; startedService = true; cleanup["processes"] = "UNKNOWN"; cleanup["listener"] = "UNKNOWN"; bool started = N.StartServiceW(service.P, 0, IntPtr.Zero);
      uint startError = unchecked((uint)Marshal.GetLastWin32Error());
      ObserveStartupStatus(service); // Preserve StartService error before this independent read.
      if (!started) throw new Refused("scm", startError);
      Poll(delegate { ObserveStartupStatus(service); return ServiceState(service) == 4; }, 20000, "startup");
      ObserveStartupStatus(service); ConfigMatch(service);
      uint servicePid = ServicePid(service); serviceProcess = new H(N.OpenProcess(0x00101400, false, servicePid), false);
      var serviceFacts = ProcessFacts(serviceProcess, servicePid, sid, digest); serviceFacts["role"] = "service";
      report["scm"] = D("state", "OBSERVED", "fixed_config_match", true, "sid_sha256", Sha(Encoding.ASCII.GetBytes(sid)), "pid", servicePid);
      Poll(delegate { return ListenerPids().Count == 1; }, 20000, "startup"); var pids = ListenerPids(); Need(pids.Count == 1 && pids[0] != servicePid, "ownership");
      child = new H(N.OpenProcess(0x00101400, false, pids[0]), false); var childFacts = ProcessFacts(child, pids[0], sid, digest);
      childFacts["role"] = "child"; Need((uint)childFacts["parent_pid"] == servicePid && UInt64.Parse((string)serviceFacts["creation_filetime"]) <= UInt64.Parse((string)childFacts["creation_filetime"]), "ownership");
      var processes = (List<object>)report["processes"]; processes.Add(serviceFacts); processes.Add(childFacts);
      stage = "job";
      using (var job = new H(N.OpenJobObjectW(0x20004, false, JobName), false)) {
        JobSecurity(job, sid); bool member; Win(N.IsProcessInJob(child.P, job.P, out member), "job"); if (!(member)) throw new Refused("ownership", 0x4a4f420b);
        var limit = new N.JOB_LIMIT(); var accounting = new N.JOB_ACCOUNTING();
        Win(N.QueryJobLimit(job.P, 9, ref limit, (uint)Marshal.SizeOf(typeof(N.JOB_LIMIT)), IntPtr.Zero), "job");
        Win(N.QueryJobAccounting(job.P, 1, ref accounting, (uint)Marshal.SizeOf(typeof(N.JOB_ACCOUNTING)), IntPtr.Zero), "job");
        if (!((limit.Basic.Flags & 0x2000) != 0)) throw new Refused("ownership", 0x4a4f420c);
        if (!(accounting.Active == 1)) throw new Refused("ownership", FailedJobMembers(job, pids[0], servicePid));
        report["job"] = D("state", "OBSERVED", "kill_on_close", true, "child_member", true, "protected_dacl_match", true, "active_processes", accounting.Active);
      } // Do not retain a second Job handle across service stop/last-handle kill.
      report["listener"] = D("state", "OBSERVED", "family", "IPv4", "address_class", "LOOPBACK", "port", Port, "owned_pid", pids[0]);
      listenerObserved = true; complete = true;
    } catch (Refused e) { report["error_class"] = e.Class; report["error_code"] = e.Code; }
      catch { report["error_class"] = "unexpected"; report["error_code"] = 0; }
    finally {
      report["stage"] = stage;
      try {
        bool stopped = !startedService;
        if (createdService && service != null) {
          if (serviceConfigured) ConfigMatch(service); else BasicConfigMatch(service); // Partial setup still owns only its captured registration.
          if (startedService) {
            N.SERVICE_STATUS status;
            bool request = N.ControlService(service.P, 1, out status); int code = Marshal.GetLastWin32Error();
            Need(request || code == 1062, "cleanup");
            Poll(delegate { return ServiceState(service) == 1; }, 30000, "cleanup"); stopped = true;
          }
          if (stopped && (serviceProcess == null || N.WaitForSingleObject(serviceProcess.P, 10000) == 0) &&
              (child == null || N.WaitForSingleObject(child.P, 10000) == 0)) {
            cleanup["processes"] = startedService ? (serviceProcess != null && child != null ? "OBSERVED_TERMINAL" : "UNKNOWN") : "NOT_CREATED";
            Win(N.DeleteService(service.P), "cleanup"); service.Dispose(); service = null;
            Poll(delegate { return ServiceMissing(scm); }, 10000, "cleanup"); cleanup["scm"] = "OBSERVED_ABSENT";
            if (listenerObserved && ListenerPids().Count == 0 && RefusedConnect()) cleanup["listener"] = "OBSERVED_ABSENT";
            // Marker/root use original deletion handles; image joins a new handle to the retained READ identity/hash.
            bool filesGone = true;
            if (marker != null) { FileFacts(marker, false, sid); filesGone &= DeleteFileHandle(marker, Marker); marker = null; }
            if (exe != null) { if (DeleteExecutableHandle(exe, sid, executableDigest)) exe = null; else filesGone = false; }
            if (createdRoot && filesGone && MissingPath(Exe) && MissingPath(Marker)) {
              cleanup["files"] = "OBSERVED_ABSENT"; FileFacts(root, true, sid);
              if (DeleteFileHandle(root, Root)) { root = null; cleanup["root"] = "OBSERVED_ABSENT"; }
            }
          }
        }
      } catch { complete = false; if ((string)report["error_class"] == "none") report["error_class"] = "cleanup"; }
      foreach (H h in new H[] { child, serviceProcess, marker, exe, root, parent, service, scm }) if (h != null) h.Dispose();
    }
    bool cleaned = (string)cleanup["scm"] == "OBSERVED_ABSENT" && (string)cleanup["processes"] == "OBSERVED_TERMINAL" &&
      (string)cleanup["listener"] == "OBSERVED_ABSENT" && (string)cleanup["files"] == "OBSERVED_ABSENT" && (string)cleanup["root"] == "OBSERVED_ABSENT";
    report["outcome"] = complete && cleaned ? "OBSERVED" : (stage == "preflight" ? "REFUSED" : "UNKNOWN");
    string encoded = Json(report); Need(encoded.Length <= 16384, "report"); Console.WriteLine(encoded); return complete && cleaned ? 0 : 1;
  }
  static uint ServiceControl(uint code, uint type, IntPtr data, IntPtr context) { if (code == 1 || code == 5) ServiceStop.Set(); return 0; }
  static void Status(uint state, bool bad) {
    var s = new N.SERVICE_STATUS { Type = 0x10, State = state, Accepted = state == 4 ? 5U : 0U,
      Win32Exit = bad ? 1066U : 0U, ServiceExit = bad ? ServiceCheckpoint : 0U, Checkpoint = state == 2 || state == 3 ? 1U : 0U,
      WaitHint = state == 2 || state == 3 ? 30000U : 0U };
    Win(N.SetServiceStatus(StatusHandle, ref s), "scm");
  }
  static void ServiceMain(uint argc, IntPtr argv) {
    // SCM argument pointers are deliberately ignored. Only the fixed entry role is implemented.
    H job = null, child = null, thread = null; bool bad = false;
    try {
      StatusHandle = N.RegisterServiceCtrlHandlerExW(ServiceName, HandlerDelegate, IntPtr.Zero); Win(StatusHandle != IntPtr.Zero, "scm"); Status(2, false);
      ServiceCheckpoint = 2; Need(String.Equals(Assembly.GetExecutingAssembly().Location, Exe, StringComparison.OrdinalIgnoreCase), "ownership");
      ServiceCheckpoint = 3; string sid = ServiceSID(); Need(TokenSID(N.GetCurrentProcess()) == sid, "ownership");
      ServiceCheckpoint = 4;
      using (var sd = new SD("O:" + sid + "D:P(A;;0x1f003f;;;BA)(A;;0x1f003f;;;SY)(A;;0x1f003f;;;" + sid + ")")) {
        N.SECURITY_ATTRIBUTES sa = sd.Attributes(); IntPtr raw = N.CreateJobObjectW(ref sa, JobName); int code = Marshal.GetLastWin32Error();
        job = new H(raw, false); Need(code != 183, "preexisting");
      }
      ServiceCheckpoint = 5; Need(Marshal.SizeOf(typeof(N.JOB_LIMIT)) == 144, "abi"); var limits = new N.JOB_LIMIT(); limits.Basic.Flags = 0x2000;
      Win(N.SetInformationJobObject(job.P, 9, ref limits, 144), "job");
      ServiceCheckpoint = 6; var start = new N.STARTUPINFO { Size = Marshal.SizeOf(typeof(N.STARTUPINFO)) }; var pi = new N.PROCESS_INFORMATION();
      IntPtr env = Marshal.StringToHGlobalUni("SystemRoot=C:\\Windows\0WINDIR=C:\\Windows\0PATH=C:\\Windows\\System32\0\0");
      try { Win(N.CreateProcessW(Exe, new StringBuilder("\"" + Exe + "\" --child"), IntPtr.Zero, IntPtr.Zero, false,
        CREATE_SUSPENDED | DETACHED_PROCESS | CREATE_UNICODE_ENVIRONMENT, env, Root, ref start, out pi), "process"); }
      finally { Marshal.FreeHGlobal(env); }
      child = new H(pi.Process, false); thread = new H(pi.Thread, false);
      ServiceCheckpoint = 7; if (!N.AssignProcessToJobObject(job.P, child.P)) { N.TerminateProcess(child.P, 1); N.WaitForSingleObject(child.P, 5000); throw new Refused("job", 0); }
      ServiceCheckpoint = 8; Need(N.ResumeThread(thread.P) != uint.MaxValue, "process"); thread.Dispose(); thread = null; ServiceCheckpoint = 9; Status(4, false);
      ServiceStop.WaitOne(LimitMs); ServiceCheckpoint = 10; Status(3, false);
    } catch { bad = true; }
    finally {
      if (thread != null) thread.Dispose(); if (job != null) job.Dispose();
      if (child != null) { N.WaitForSingleObject(child.P, 10000); child.Dispose(); }
      if (StatusHandle != IntPtr.Zero) { try { Status(1, bad); } catch { } }
    }
  }
  static int Child() {
    Need(String.Equals(Assembly.GetExecutingAssembly().Location, Exe, StringComparison.OrdinalIgnoreCase), "ownership");
    using (var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp)) {
      socket.ExclusiveAddressUse = true; socket.Bind(new IPEndPoint(IPAddress.Loopback, Port)); socket.Listen(1); Thread.Sleep(LimitMs);
    } return 0;
  }
  static string Json(object value) {
    if (value == null) return "null"; if (value is bool) return (bool)value ? "true" : "false";
    if (value is string) { var s = new StringBuilder("\""); foreach (char c in (string)value) { if (c == '\\' || c == '"') s.Append('\\'); Need(c >= 32 && c <= 126, "report"); s.Append(c); } return s.Append('"').ToString(); }
    var map = value as Dictionary<string, object>; if (map != null) { var parts = new List<string>(); foreach (var p in map) parts.Add(Json(p.Key) + ":" + Json(p.Value)); return "{" + String.Join(",", parts.ToArray()) + "}"; }
    var list = value as List<object>; if (list != null) { var parts = new List<string>(); foreach (object p in list) parts.Add(Json(p)); return "[" + String.Join(",", parts.ToArray()) + "]"; }
    Need(value is int || value is uint, "report"); return Convert.ToString(value, System.Globalization.CultureInfo.InvariantCulture);
  }
  public static int Main(string[] args) {
    if (args.Length != 1) return 2;
    try {
      if (args[0] == "--probe") return Probe();
      if (args[0] == "--child") return Child();
      if (args[0] == "--service") {
        Need(IntPtr.Size == 8, "abi");
        IntPtr name = IntPtr.Zero, table = IntPtr.Zero;
        try {
          name = Marshal.StringToHGlobalUni(ServiceName); table = Marshal.AllocHGlobal(32);
          Marshal.WriteIntPtr(table, 0, name);
          Marshal.WriteIntPtr(table, 8, Marshal.GetFunctionPointerForDelegate(MainDelegate));
          Marshal.WriteIntPtr(table, 16, IntPtr.Zero); Marshal.WriteIntPtr(table, 24, IntPtr.Zero);
          Win(N.StartServiceCtrlDispatcherW(table), "scm"); return 0;
        } finally {
          GC.KeepAlive(MainDelegate); GC.KeepAlive(HandlerDelegate);
          if (table != IntPtr.Zero) Marshal.FreeHGlobal(table);
          if (name != IntPtr.Zero) Marshal.FreeHGlobal(name);
        }
      }
    } catch { return 1; } return 2;
  }

  static class N {
    [StructLayout(LayoutKind.Sequential)] internal struct FILETIME { internal uint Low, High; }
    [StructLayout(LayoutKind.Sequential)] internal struct BOOT_ENV { internal Guid Id; internal uint Firmware; internal ulong Flags; }
    [StructLayout(LayoutKind.Sequential)] internal struct TIME_OF_DAY { internal long BootTime, CurrentTime, ZoneBias; internal uint ZoneId, Reserved; internal ulong BootBias, SleepBias; }
    [StructLayout(LayoutKind.Sequential)] internal struct BASIC_PROCESS { internal int Exit; internal IntPtr Peb, Affinity; internal int Priority; internal UIntPtr Pid, Parent; }
    [StructLayout(LayoutKind.Sequential)] internal struct SECURITY_ATTRIBUTES { internal int Length; internal IntPtr Descriptor; internal int Inherit; }
    [StructLayout(LayoutKind.Sequential)] internal struct BY_HANDLE { internal uint Attributes; internal FILETIME Created, Accessed, Written; internal uint Volume, SizeHigh, SizeLow, Links, IdHigh, IdLow; }
    [StructLayout(LayoutKind.Sequential)] internal struct FILE_ID_INFO { internal ulong Volume; [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] internal byte[] Id; }
    [StructLayout(LayoutKind.Sequential)] internal struct DISPOSITION { internal byte Delete; }
    [StructLayout(LayoutKind.Sequential)] internal struct ACL_SIZE { internal uint Count, Used, Free; }
    [StructLayout(LayoutKind.Sequential)] internal struct SERVICE_SID { internal uint Type; }
    [StructLayout(LayoutKind.Sequential)] internal struct FAILURE_FLAG { internal int Enabled; }
    [StructLayout(LayoutKind.Sequential)] internal struct FAILURE_ACTIONS { internal uint Reset; internal IntPtr Reboot, Command; internal uint Count; internal IntPtr Actions; }
    [StructLayout(LayoutKind.Sequential)] internal struct SERVICE_CONFIG { internal uint Type, Start, Error; internal IntPtr Binary, Group; internal uint Tag; internal IntPtr Dependencies, Account, Display; }
    [StructLayout(LayoutKind.Sequential)] internal struct SERVICE_STATUS { internal uint Type, State, Accepted, Win32Exit, ServiceExit, Checkpoint, WaitHint; }
    [StructLayout(LayoutKind.Sequential)] internal struct SERVICE_STATUS_PROCESS { internal uint Type, State, Accepted, Win32Exit, ServiceExit, Checkpoint, WaitHint, Pid, Flags; }
    [StructLayout(LayoutKind.Sequential)] internal struct JOB_BASIC { internal long ProcessTime, JobTime; internal uint Flags; internal UIntPtr MinSet, MaxSet; internal uint Active; internal UIntPtr Affinity; internal uint Priority, Scheduling; }
    [StructLayout(LayoutKind.Sequential)] internal struct IO_COUNTERS { internal ulong ReadOps, WriteOps, OtherOps, ReadBytes, WriteBytes, OtherBytes; }
    [StructLayout(LayoutKind.Sequential)] internal struct JOB_LIMIT { internal JOB_BASIC Basic; internal IO_COUNTERS IO; internal UIntPtr ProcessMemory, JobMemory, PeakProcessMemory, PeakJobMemory; }
    [StructLayout(LayoutKind.Sequential)] internal struct JOB_ACCOUNTING { internal long User, Kernel, PeriodUser, PeriodKernel; internal uint Faults, Total, Active, Terminated; }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] internal struct STARTUPINFO { internal int Size; internal IntPtr Reserved, Desktop, Title; internal uint X, Y, XSize, YSize, XChars, YChars, Fill, Flags; internal ushort Show, ReservedSize; internal IntPtr Reserved2, Input, Output, Error; }
    [StructLayout(LayoutKind.Sequential)] internal struct PROCESS_INFORMATION { internal IntPtr Process, Thread; internal uint Pid, Tid; }
    [UnmanagedFunctionPointer(CallingConvention.Winapi)] internal delegate void ServiceMain(uint argc, IntPtr argv);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)] internal delegate uint Handler(uint control, uint eventType, IntPtr eventData, IntPtr context);
    [DllImport("ntdll.dll", EntryPoint = "NtQuerySystemInformation")] internal static extern int NtQueryBoot(int c, ref BOOT_ENV b, uint n, out uint returned);
    [DllImport("ntdll.dll", EntryPoint = "NtQuerySystemInformation")] internal static extern int NtQueryTime(int c, ref TIME_OF_DAY b, uint n, out uint returned);
    [DllImport("ntdll.dll")] internal static extern int NtQueryInformationProcess(IntPtr h, int c, ref BASIC_PROCESS b, uint n, out uint returned);
    [DllImport("kernel32.dll")] internal static extern void GetSystemTimePreciseAsFileTime(out FILETIME x);
    [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool QueryPerformanceCounter(out long x);
    [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool QueryPerformanceFrequency(out long x);
    [DllImport("kernel32.dll")] internal static extern ulong GetTickCount64();
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)] internal static extern uint GetModuleFileNameW(IntPtr module, StringBuilder path, int size);
    [DllImport("kernel32.dll", SetLastError = true)] internal static extern IntPtr GetModuleHandleW([MarshalAs(UnmanagedType.LPWStr)] string name);
    [DllImport("kernel32.dll", SetLastError = true)] internal static extern IntPtr LoadLibraryExW([MarshalAs(UnmanagedType.LPWStr)] string name, IntPtr file, uint flags);
    [DllImport("kernel32.dll")] internal static extern uint GetCurrentProcessId();
    [DllImport("kernel32.dll")] internal static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll", SetLastError = true)] internal static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
    [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool GetProcessTimes(IntPtr h, out FILETIME created, out FILETIME exited, out FILETIME kernel, out FILETIME user);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)] internal static extern bool QueryFullProcessImageNameW(IntPtr h, uint flags, StringBuilder path, ref uint size);
    [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll", SetLastError = true)] internal static extern uint WaitForSingleObject(IntPtr h, uint timeout);
    [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool TerminateProcess(IntPtr h, uint code);
    [DllImport("kernel32.dll", SetLastError = true)] internal static extern uint ResumeThread(IntPtr h);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)] internal static extern bool CreateProcessW(string app, StringBuilder line, IntPtr psa, IntPtr tsa, bool inherit, uint flags, IntPtr env, string directory, ref STARTUPINFO si, out PROCESS_INFORMATION pi);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)] internal static extern IntPtr CreateFileW(string p, uint access, uint share, IntPtr sa, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", SetLastError = true, CharSet = CharSet.Unicode)] internal static extern IntPtr CreateFileNewW(string p, uint access, uint share, ref SECURITY_ATTRIBUTES sa, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)] internal static extern bool CreateDirectoryW(string p, ref SECURITY_ATTRIBUTES sa);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)] internal static extern uint GetFileAttributesW(string p);
    [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool GetFileInformationByHandle(IntPtr h, out BY_HANDLE x);
    [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool GetFileInformationByHandleEx(IntPtr h, int c, ref FILE_ID_INFO x, uint n);
    [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool SetFileInformationByHandle(IntPtr h, int c, ref DISPOSITION x, uint n);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)] internal static extern uint GetFinalPathNameByHandleW(IntPtr h, StringBuilder path, uint n, uint flags);
    [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool WriteFile(IntPtr h, byte[] data, uint n, out uint written, IntPtr overlapped);
    [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool FlushFileBuffers(IntPtr h);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)] internal static extern IntPtr CreateJobObjectW(ref SECURITY_ATTRIBUTES sa, string name);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)] internal static extern IntPtr OpenJobObjectW(uint access, bool inherit, string name);
    [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool SetInformationJobObject(IntPtr h, int c, ref JOB_LIMIT x, uint n);
    [DllImport("kernel32.dll", EntryPoint = "QueryInformationJobObject", SetLastError = true)] internal static extern bool QueryJobLimit(IntPtr h, int c, ref JOB_LIMIT x, uint n, IntPtr returned);
    [DllImport("kernel32.dll", EntryPoint = "QueryInformationJobObject", SetLastError = true)] internal static extern bool QueryJobAccounting(IntPtr h, int c, ref JOB_ACCOUNTING x, uint n, IntPtr returned);
    [DllImport("kernel32.dll", EntryPoint = "QueryInformationJobObject", SetLastError = true)] internal static extern bool QueryJobProcessIds(IntPtr h, int c, IntPtr buffer, uint n, out uint returned);
    [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
    [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool IsProcessInJob(IntPtr process, IntPtr job, out bool member);
    [DllImport("kernel32.dll")] internal static extern IntPtr LocalFree(IntPtr p);
    [DllImport("advapi32.dll", SetLastError = true)] internal static extern bool OpenProcessToken(IntPtr h, uint access, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true)] internal static extern bool GetTokenInformation(IntPtr token, int c, IntPtr b, uint n, out uint returned);
    [DllImport("advapi32.dll", SetLastError = true)] internal static extern bool IsValidSid(IntPtr sid);
    [DllImport("advapi32.dll", SetLastError = true)] internal static extern bool ConvertSidToStringSidW(IntPtr sid, out IntPtr text);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] internal static extern bool LookupAccountNameW(string system, string name, byte[] sid, ref uint size, StringBuilder domain, ref uint chars, out int use);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] internal static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string text, uint revision, out IntPtr sd, IntPtr size);
    [DllImport("advapi32.dll")] internal static extern uint GetSecurityInfo(IntPtr h, int kind, uint flags, out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr descriptor);
    [DllImport("advapi32.dll", SetLastError = true)] internal static extern bool GetSecurityDescriptorControl(IntPtr sd, out ushort control, out uint revision);
    [DllImport("advapi32.dll", SetLastError = true)] internal static extern bool GetAclInformation(IntPtr acl, out ACL_SIZE info, uint size, int c);
    [DllImport("advapi32.dll", SetLastError = true)] internal static extern bool GetAce(IntPtr acl, uint index, out IntPtr ace);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] internal static extern IntPtr OpenSCManagerW(string machine, string db, uint access);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] internal static extern IntPtr OpenServiceW(IntPtr scm, string name, uint access);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] internal static extern IntPtr CreateServiceW(IntPtr scm, string name, string display, uint access, uint type, uint start, uint error, string binary, string group, IntPtr tag, string dependencies, string account, string password);
    [DllImport("advapi32.dll", SetLastError = true)] internal static extern bool CloseServiceHandle(IntPtr h);
    [DllImport("advapi32.dll", SetLastError = true)] internal static extern bool QueryServiceStatusEx(IntPtr h, int c, out SERVICE_STATUS_PROCESS s, uint n, out uint returned);
    [DllImport("advapi32.dll", SetLastError = true)] internal static extern bool QueryServiceConfigW(IntPtr h, IntPtr b, uint n, out uint returned);
    [DllImport("advapi32.dll", SetLastError = true)] internal static extern bool QueryServiceConfig2W(IntPtr h, uint c, IntPtr b, uint n, out uint returned);
    [DllImport("advapi32.dll", EntryPoint = "ChangeServiceConfig2W", SetLastError = true)] internal static extern bool ChangeServiceSid(IntPtr h, uint c, ref SERVICE_SID x);
    [DllImport("advapi32.dll", EntryPoint = "ChangeServiceConfig2W", SetLastError = true)] internal static extern bool ChangeServiceFailureFlag(IntPtr h, uint c, ref FAILURE_FLAG x);
    [DllImport("advapi32.dll", EntryPoint = "ChangeServiceConfig2W", SetLastError = true)] internal static extern bool ChangeServiceFailure(IntPtr h, uint c, ref FAILURE_ACTIONS x);
    [DllImport("advapi32.dll", SetLastError = true)] internal static extern bool StartServiceW(IntPtr h, uint count, IntPtr args);
    [DllImport("advapi32.dll", SetLastError = true)] internal static extern bool ControlService(IntPtr h, uint c, out SERVICE_STATUS status);
    [DllImport("advapi32.dll", SetLastError = true)] internal static extern bool DeleteService(IntPtr h);
    [DllImport("advapi32.dll", SetLastError = true)] internal static extern bool SetServiceStatus(IntPtr h, ref SERVICE_STATUS status);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] internal static extern IntPtr RegisterServiceCtrlHandlerExW(string name, Handler handler, IntPtr context);
    [DllImport("advapi32.dll", EntryPoint = "StartServiceCtrlDispatcherW", ExactSpelling = true, SetLastError = true)] internal static extern bool StartServiceCtrlDispatcherW(IntPtr table);
    [DllImport("iphlpapi.dll")] internal static extern uint GetExtendedTcpTable(IntPtr b, ref uint n, bool sorted, uint family, uint c, uint reserved);
    [DllImport("shell32.dll")] internal static extern bool IsUserAnAdmin();
  }
}
