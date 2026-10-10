// Checks a licence key before the Worker emails it: the same format and signature Guard verifies
// (crates/zunder-guard-core/src/licence.rs: "zgl1_" + base64url(payload JSON) + "." +
// base64url(ed25519 signature over the payload's bytes)). The Worker never signs; it only checks
// that what Jonas's command posted is a real key for this order.

export interface LicenceTerms {
  licensee: string;
  expires_at_ms: number;
  features: string[];
  accounts: string[];
  builder?: { address: string; fee_tenths_bp: number };
}

const PREFIX = "zgl1_";
const MAX_LEN = 4_096;

function b64urlDecode(s: string): Uint8Array<ArrayBuffer> | null {
  if (!/^[A-Za-z0-9_-]*$/.test(s)) return null;
  const pad = s.length % 4 === 2 ? "==" : s.length % 4 === 3 ? "=" : s.length % 4 === 0 ? "" : null;
  if (pad === null) return null;
  try {
    const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + pad);
    return Uint8Array.from(bin, (c) => c.charCodeAt(0));
  } catch {
    return null;
  }
}

/** base64url without padding, as Rust's URL_SAFE_NO_PAD writes it. */
function b64urlEncode(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function hexBytes(hex: string): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  return out;
}

/** The key's terms if its signature verifies against `publicKeyHex`; null otherwise. */
export async function verifyLicence(key: string, publicKeyHex: string): Promise<LicenceTerms | null> {
  const k = key.trim();
  if (k.length > MAX_LEN || !k.startsWith(PREFIX)) return null;
  const [p64, s64, extra] = k.slice(PREFIX.length).split(".");
  if (p64 === undefined || s64 === undefined || extra !== undefined) return null;
  const payload = b64urlDecode(p64);
  const sig = b64urlDecode(s64);
  if (!payload || !sig || sig.length !== 64) return null;
  try {
    const pub = await crypto.subtle.importKey("raw", hexBytes(publicKeyHex), { name: "Ed25519" }, false, ["verify"]);
    if (!(await crypto.subtle.verify({ name: "Ed25519" }, pub, sig, payload))) return null;
  } catch {
    return null;
  }
  let terms: unknown;
  try {
    terms = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(payload));
  } catch {
    return null;
  }
  // Guard's own rules (licence.rs): no unknown fields, a licensee of 1 to 200 bytes, an integer
  // expiry, known features only; and canonical base64url, as Rust's decoder demands.
  if (b64urlEncode(payload) !== p64 || b64urlEncode(sig) !== s64) return null;
  if (!terms || typeof terms !== "object" || Array.isArray(terms)) return null;
  const t = terms as Partial<LicenceTerms> & Record<string, unknown>;
  if (Object.keys(t).some((k) => !["licensee", "expires_at_ms", "features", "accounts", "builder"].includes(k))) return null;
  if (typeof t.licensee !== "string" || t.licensee.trim() === "" || new TextEncoder().encode(t.licensee).length > 200) return null;
  if (typeof t.expires_at_ms !== "number" || !Number.isSafeInteger(t.expires_at_ms)) return null;
  if (!Array.isArray(t.features) || !t.features.every((f) => f === "fee_free")) return null;
  // Account-bound keys only: Guard honours older unbound keys for no account. Match its
  // 50-account bound and case-insensitive duplicate check before sending anything to a buyer.
  if (!Array.isArray(t.accounts) || t.accounts.length < 1 || t.accounts.length > 50) return null;
  if (!t.accounts.every((a) => typeof a === "string" && /^0x[0-9a-fA-F]{40}$/.test(a))) return null;
  const accounts = t.accounts.map((a) => a.toLowerCase());
  if (new Set(accounts).size !== accounts.length) return null;
  return { ...t, accounts } as LicenceTerms;
}
