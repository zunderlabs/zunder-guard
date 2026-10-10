// Pure closed report gate. Does not execute native APIs or turn metadata into admission.
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
public static class ReportGate {
  sealed class Parser {
    readonly string text; int at, nodes;
    internal Parser(string x) { Need(x != null && x.Length > 0 && x.Length <= 16384); foreach (char c in x) Need(c <= 127); text = x; }
    void White() { while (at < text.Length && " \r\n\t".IndexOf(text[at]) >= 0) at++; }
    char Take() { Need(at < text.Length); return text[at++]; }
    string String() {
      Need(Take() == '"'); var b = new StringBuilder();
      while (true) { char c = Take(); if (c == '"') return b.ToString(); Need(c >= 32);
        if (c == '\\') { c = Take(); if (c == '"' || c == '\\' || c == '/') b.Append(c);
          else if (c == 'u') { string h = ""; for (int n = 0; n < 4; n++) h += Take(); uint code; Need(UInt32.TryParse(h, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out code) && code >= 32 && code <= 127); b.Append((char)code); }
          else Need(false);
        } else b.Append(c); Need(b.Length <= 128);
      }
    }
    object Value(int depth) {
      Need(depth <= 8 && ++nodes <= 512); White(); Need(at < text.Length); char c = text[at];
      if (c == '"') return String();
      if (c == '{') { at++; var d = new Dictionary<string, object>(); White(); if (text[at] == '}') { at++; return d; }
        while (true) { White(); string key = String(); White(); Need(Take() == ':'); object v = Value(depth + 1); Need(!d.ContainsKey(key)); d.Add(key, v); White(); c = Take(); if (c == '}') return d; Need(c == ','); }
      }
      if (c == '[') { at++; var a = new List<object>(); White(); if (text[at] == ']') { at++; return a; }
        while (true) { a.Add(Value(depth + 1)); Need(a.Count <= 3); White(); c = Take(); if (c == ']') return a; Need(c == ','); }
      }
      foreach (string token in new string[] { "true", "false", "null" }) if (text.Substring(at).StartsWith(token, StringComparison.Ordinal)) { at += token.Length; return token == "null" ? null : (object)(token == "true"); }
      int start = at; while (at < text.Length && text[at] >= '0' && text[at] <= '9') at++;
      string number = text.Substring(start, at - start); uint result = 0; Need(Regex.IsMatch(number, @"^(0|[1-9][0-9]{0,9})$") && UInt32.TryParse(number, out result)); return result;
    }
    internal object Parse() { object x = Value(0); White(); Need(at == text.Length); return x; }
  }
  static void Need(bool yes) { if (!yes) throw new FormatException(); }
  static Dictionary<string, object> Obj(object x, params string[] names) {
    var d = x as Dictionary<string, object>; Need(d != null && d.Count == names.Length); foreach (string name in names) Need(d.ContainsKey(name)); return d;
  }
  static string Str(object x) { Need(x is string); return (string)x; }
  static uint Num(object x) { Need(x is uint); return (uint)x; }
  static bool Bool(object x) { Need(x is bool); return (bool)x; }
  static void Eq(object x, string expected) { Need(Str(x) == expected); }
  static void Enum(object x, params string[] values) { Need(Array.IndexOf(values, Str(x)) >= 0); }
  static string Hex(object x, int bytes) { string s = Str(x); Need(Regex.IsMatch(s, "^[0-9a-f]{" + bytes + "}$")); return s; }
  static ulong Ticks(object x) { string s = Str(x); ulong n = 0; Need(Regex.IsMatch(s, @"^(0|[1-9][0-9]{0,19})$") && UInt64.TryParse(s, out n)); return n; }
  static List<object> ArrayOf(object x, int maximum) { var a = x as List<object>; Need(a != null && a.Count <= maximum); return a; }
  public static string Validate(string raw) {
    try {
      var r = Obj(new Parser(raw).Parse(), "schema", "kind", "outcome", "stage", "error_class", "error_code", "actual_native_getter_executed",
        "source_admitted", "runtime_admitted", "release_ready", "production_windows_service_acceptance", "native_credential_retention_proven",
        "same_host_reboot_proven", "all_owned_processes_gone", "self_exit", "vm_removal", "receipt_memory_absence", "boot", "processes", "files", "startup_status", "scm", "job", "listener", "cleanup");
      Need(Num(r["schema"]) == 2); Eq(r["kind"], "WINDOWS_NO_KEY_NATIVE_PHASE_ZERO"); Enum(r["outcome"], "OBSERVED", "UNKNOWN", "REFUSED");
      Enum(r["stage"], "preflight", "scm", "files", "startup", "job");
      Enum(r["error_class"], "none", "handle", "security", "process", "abi", "boot_environment", "time_of_day", "clock", "clock_guard", "ownership", "file", "scm", "listener", "startup", "job", "preexisting", "privilege", "cleanup", "unexpected", "report"); Num(r["error_code"]);
      Need(Bool(r["actual_native_getter_executed"]));
      foreach (string f in new string[] { "source_admitted", "runtime_admitted", "release_ready", "production_windows_service_acceptance", "native_credential_retention_proven", "same_host_reboot_proven", "all_owned_processes_gone" }) Need(!Bool(r[f]));
      Eq(r["self_exit"], "UNKNOWN"); Eq(r["vm_removal"], "UNKNOWN"); Eq(r["receipt_memory_absence"], "NOT_EXERCISED");
      var b = Obj(r["boot"], "state", "guid", "boot_filetime", "current_filetime", "observation_before_filetime", "observation_after_filetime", "qpc_before", "qpc_after", "qpc_frequency", "uptime_ms");
      Enum(b["state"], "OBSERVED", "UNKNOWN");
      if (Str(b["state"]) == "OBSERVED") {
        Guid id; Need(Guid.TryParseExact(Str(b["guid"]), "D", out id) && id != Guid.Empty && id.ToString("D") == Str(b["guid"]));
        ulong before = Ticks(b["observation_before_filetime"]), after = Ticks(b["observation_after_filetime"]), current = Ticks(b["current_filetime"]);
        Need(Ticks(b["boot_filetime"]) > 0 && Ticks(b["boot_filetime"]) <= before && before <= current && current <= after && after - before <= 50000000);
        Need(Ticks(b["qpc_before"]) <= Ticks(b["qpc_after"]) && Ticks(b["qpc_frequency"]) > 0); Ticks(b["uptime_ms"]);
      } else foreach (var f in b) if (f.Key != "state") Need(f.Value == null);
      if (Str(r["error_class"]) == "clock_guard") Need(Str(r["stage"]) == "preflight" && Str(r["outcome"]) == "REFUSED" && Str(b["state"]) == "UNKNOWN" && Num(r["error_code"]) >= 1 && Num(r["error_code"]) <= 11);
      var processes = ArrayOf(r["processes"], 2); var roles = new Dictionary<string, Dictionary<string, object>>();
      foreach (object x in processes) {
        var p = Obj(x, "role", "pid", "creation_filetime", "parent_pid", "image_sha256", "fixed_image_match", "virtual_sid_match", "observation_before_filetime", "observation_after_filetime");
        Enum(p["role"], "service", "child"); Need(!roles.ContainsKey(Str(p["role"]))); roles.Add(Str(p["role"]), p);
        Need(Num(p["pid"]) > 0 && Num(p["parent_pid"]) > 0 && Bool(p["fixed_image_match"]) && Bool(p["virtual_sid_match"])); Hex(p["image_sha256"], 64);
        Need(Ticks(p["creation_filetime"]) > 0 && Ticks(p["observation_before_filetime"]) <= Ticks(p["observation_after_filetime"]) && Ticks(p["creation_filetime"]) <= Ticks(p["observation_after_filetime"]));
      }
      var files = ArrayOf(r["files"], 3); var fileRoles = new Dictionary<string, Dictionary<string, object>>();
      foreach (object x in files) {
        var f = Obj(x, "role", "file_id", "volume_serial", "links", "reparse", "protected_dacl_match", "owner_class", "sha256");
        Enum(f["role"], "root", "executable", "marker"); Need(!fileRoles.ContainsKey(Str(f["role"]))); fileRoles.Add(Str(f["role"]), f);
        Hex(f["file_id"], 32); Ticks(f["volume_serial"]); Need(Num(f["links"]) > 0 && !Bool(f["reparse"]) && Bool(f["protected_dacl_match"])); Eq(f["owner_class"], "ADMINISTRATORS");
        if (Str(f["role"]) == "root") Need(f["sha256"] == null); else { Need(Num(f["links"]) == 1); if (f["sha256"] != null) Hex(f["sha256"], 64); else Need(Str(r["outcome"]) != "OBSERVED"); }
      }
      var startup = Obj(r["startup_status"], "state", "service_state", "win32_exit", "service_exit");
      Enum(startup["state"], "OBSERVED", "UNKNOWN");
      if (Str(startup["state"]) == "OBSERVED") { Need(Num(startup["service_state"]) >= 1 && Num(startup["service_state"]) <= 7); Num(startup["win32_exit"]); Num(startup["service_exit"]); }
      else Need(startup["service_state"] == null && startup["win32_exit"] == null && startup["service_exit"] == null);
      var scm = Obj(r["scm"], "state", "fixed_config_match", "sid_sha256", "pid"); Enum(scm["state"], "OBSERVED", "UNKNOWN");
      if (Str(scm["state"]) == "OBSERVED") { Need(Bool(scm["fixed_config_match"]) && Num(scm["pid"]) > 0); Hex(scm["sid_sha256"], 64); }
      else Need(!Bool(scm["fixed_config_match"]) && scm["sid_sha256"] == null && scm["pid"] == null);
      var job = Obj(r["job"], "state", "kill_on_close", "child_member", "protected_dacl_match", "active_processes"); Enum(job["state"], "OBSERVED", "UNKNOWN");
      if (Str(job["state"]) == "OBSERVED") Need(Bool(job["kill_on_close"]) && Bool(job["child_member"]) && Bool(job["protected_dacl_match"]) && Num(job["active_processes"]) == 1);
      else Need(!Bool(job["kill_on_close"]) && !Bool(job["child_member"]) && !Bool(job["protected_dacl_match"]) && job["active_processes"] == null);
      var listener = Obj(r["listener"], "state", "family", "address_class", "port", "owned_pid"); Enum(listener["state"], "OBSERVED", "UNKNOWN");
      Eq(listener["family"], "IPv4"); Eq(listener["address_class"], "LOOPBACK"); Need(Num(listener["port"]) == 18547);
      if (Str(listener["state"]) == "OBSERVED") Need(Num(listener["owned_pid"]) > 0); else Need(listener["owned_pid"] == null);
      var cleanup = Obj(r["cleanup"], "scm", "processes", "listener", "files", "root");
      foreach (string f in new string[] { "scm", "listener", "files", "root" }) Enum(cleanup[f], "OBSERVED_ABSENT", "UNKNOWN", "NOT_CREATED");
      Enum(cleanup["processes"], "OBSERVED_TERMINAL", "UNKNOWN", "NOT_CREATED");
      if (Str(r["outcome"]) == "OBSERVED") {
        Need(Str(startup["state"]) == "OBSERVED" && Num(startup["service_state"]) == 4 && Num(startup["win32_exit"]) == 0 && Num(startup["service_exit"]) == 0);
        Need(Str(r["error_class"]) == "none" && Num(r["error_code"]) == 0 && Str(b["state"]) == "OBSERVED" && processes.Count == 2 && files.Count == 3 &&
          Str(scm["state"]) == "OBSERVED" && Str(job["state"]) == "OBSERVED" && Str(listener["state"]) == "OBSERVED");
        Need(Num(roles["child"]["parent_pid"]) == Num(roles["service"]["pid"]) && Num(scm["pid"]) == Num(roles["service"]["pid"]) &&
          Num(listener["owned_pid"]) == Num(roles["child"]["pid"]) && Ticks(roles["service"]["creation_filetime"]) <= Ticks(roles["child"]["creation_filetime"]));
        foreach (var p in roles.Values) Need(Str(p["image_sha256"]) == Str(fileRoles["executable"]["sha256"]));
        foreach (string f in new string[] { "scm", "listener", "files", "root" }) Eq(cleanup[f], "OBSERVED_ABSENT"); Eq(cleanup["processes"], "OBSERVED_TERMINAL");
      }
      return raw.Trim();
    } catch { return null; }
  }
}
