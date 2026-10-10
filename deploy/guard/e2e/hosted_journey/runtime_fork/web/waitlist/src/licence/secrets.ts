// Renewal tokens and the stored licence keys. Both derive from the Worker's UNSUBSCRIBE_SECRET with
// their own labels (domain separation), so no new secret is needed and none is stored in D1:
// - the renewal token of a licence: HMAC("licence-renewal:v1:" + licence id), base64url. Only its
//   SHA-256 is in D1 (licence_renewal_tokens); a reminder recomputes the link;
// - the delivered key: AES-256-GCM under HMAC("licence-key-enc:v1"), the licence and order ids as
//   associated data, so a D1 copy alone does not give the keys away.

import { base64url, sha256Hex } from "../tokens.ts";

const enc = new TextEncoder();

async function hmacBytes(secret: string, label: string): Promise<Uint8Array<ArrayBuffer>> {
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, enc.encode(label)));
}

/** The renewal token of a licence; a new generation revokes the links sent with the old one. */
export async function renewalToken(secret: string, licenceId: string, generation = 1): Promise<string> {
  return base64url(await hmacBytes(secret, "licence-renewal:v1:" + licenceId + ":" + generation));
}

export function renewalTokenHash(token: string): Promise<string> {
  return sha256Hex("licence-renewal:" + token);
}

async function aesKey(secret: string): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", await hmacBytes(secret, "licence-key-enc:v1"), { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

function fromB64url(s: string): Uint8Array<ArrayBuffer> {
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

/** The sealed key, "v1." + base64url(IV ‖ ciphertext), so a later scheme can be told apart. */
export async function sealKey(secret: string, licenceId: string, orderId: string, key: string): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: enc.encode(licenceId + ":" + orderId) }, await aesKey(secret), enc.encode(key)));
  const out = new Uint8Array(iv.length + ct.length);
  out.set(iv);
  out.set(ct, iv.length);
  return "v1." + base64url(out);
}

/** The key, or null if the blob does not decrypt for this licence and order. */
export async function openKey(secret: string, licenceId: string, orderId: string, sealed: string): Promise<string | null> {
  if (!sealed.startsWith("v1.")) return null;
  try {
    const raw = fromB64url(sealed.slice(3));
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: raw.slice(0, 12), additionalData: enc.encode(licenceId + ":" + orderId) }, await aesKey(secret), raw.slice(12));
    return new TextDecoder().decode(pt);
  } catch {
    // A rotated secret or a tampered row: say so, without the data.
    console.error("[licence] a stored key did not open (secret rotated, or the row was changed)");
    return null;
  }
}
