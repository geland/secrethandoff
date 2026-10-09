// Sealed requests (ADR 0010): HPKE base mode, RFC 9180, with
// DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, and AES-GCM, using Web Crypto.
// Only erasable TypeScript syntax is used, so Node can run it directly.

const te = new TextEncoder();

export const SEALED_VERSION = "v1";
export const AEAD_AES128GCM = 0x0001;
export const AEAD_AES256GCM = 0x0002;
const KEM_P256 = 0x0010;
const KDF_HKDF_SHA256 = 0x0001;
const NH = 32;

export function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let i = 0;
  for (const p of parts) {
    out.set(p, i);
    i += p.length;
  }
  return out;
}

function i2osp(n: number, len: number): Uint8Array {
  const out = new Uint8Array(len);
  for (let i = len - 1; i >= 0; i--) {
    out[i] = n & 0xff;
    n >>>= 8;
  }
  return out;
}

export function toBase64Url(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

export function fromBase64Url(value: string): Uint8Array {
  const padded = value.replaceAll("-", "+").replaceAll("_", "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  return Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
}

async function hmac(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const k = await crypto.subtle.importKey("raw", (key.length ? key : new Uint8Array(NH)) as BufferSource, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", k, data as BufferSource));
}

async function expand(prk: Uint8Array, info: Uint8Array, length: number): Promise<Uint8Array> {
  const out = new Uint8Array(length);
  let t: Uint8Array = new Uint8Array(0);
  for (let i = 1, filled = 0; filled < length; i++) {
    t = await hmac(prk, concat(t, info, new Uint8Array([i])));
    out.set(t.subarray(0, Math.min(t.length, length - filled)), filled);
    filled += t.length;
  }
  return out;
}

const labeledExtract = (suite: Uint8Array, salt: Uint8Array, label: string, ikm: Uint8Array) =>
  hmac(salt, concat(te.encode("HPKE-v1"), suite, te.encode(label), ikm));

const labeledExpand = (suite: Uint8Array, prk: Uint8Array, label: string, info: Uint8Array, length: number) =>
  expand(prk, concat(i2osp(length, 2), te.encode("HPKE-v1"), suite, te.encode(label), info), length);

async function importPublic(raw: Uint8Array): Promise<CryptoKey> {
  if (raw.length !== 65 || raw[0] !== 4) throw new Error("The request key is not a P-256 public key.");
  return crypto.subtle.importKey("raw", raw as BufferSource, { name: "ECDH", namedCurve: "P-256" }, false, []);
}

type Ephemeral = { privateKey: CryptoKey; publicRaw: Uint8Array };

async function newEphemeral(): Promise<Ephemeral> {
  const pair = (await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"])) as CryptoKeyPair;
  return { privateKey: pair.privateKey, publicRaw: new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey)) };
}

/** importEphemeral builds a fixed ephemeral key, for test vectors only. */
export async function importEphemeral(sk: Uint8Array, pkRaw: Uint8Array): Promise<Ephemeral> {
  const jwk = { kty: "EC", crv: "P-256", d: toBase64Url(sk), x: toBase64Url(pkRaw.subarray(1, 33)), y: toBase64Url(pkRaw.subarray(33, 65)) };
  const privateKey = await crypto.subtle.importKey("jwk", jwk, { name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
  return { privateKey, publicRaw: pkRaw };
}

export type SealInput = {
  recipientPublicKey: Uint8Array;
  info: Uint8Array;
  plaintext: Uint8Array;
  aad?: Uint8Array;
  aeadId?: number;
  ephemeral?: Ephemeral;
};

/** seal returns enc || ciphertext, as Go's crypto/hpke Seal does. */
export async function seal(input: SealInput): Promise<Uint8Array> {
  const aeadId = input.aeadId ?? AEAD_AES256GCM;
  const nk = aeadId === AEAD_AES128GCM ? 16 : 32;
  const pkR = await importPublic(input.recipientPublicKey);
  const eph = input.ephemeral ?? (await newEphemeral());
  const dh = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: pkR }, eph.privateKey, 256));
  const kemSuite = concat(te.encode("KEM"), i2osp(KEM_P256, 2));
  const eaePrk = await labeledExtract(kemSuite, new Uint8Array(0), "eae_prk", dh);
  const shared = await labeledExpand(kemSuite, eaePrk, "shared_secret", concat(eph.publicRaw, input.recipientPublicKey), NH);

  const suite = concat(te.encode("HPKE"), i2osp(KEM_P256, 2), i2osp(KDF_HKDF_SHA256, 2), i2osp(aeadId, 2));
  const pskIdHash = await labeledExtract(suite, new Uint8Array(0), "psk_id_hash", new Uint8Array(0));
  const infoHash = await labeledExtract(suite, new Uint8Array(0), "info_hash", input.info);
  const context = concat(new Uint8Array([0]), pskIdHash, infoHash);
  const secret = await labeledExtract(suite, shared, "secret", new Uint8Array(0));
  const key = await labeledExpand(suite, secret, "key", context, nk);
  const nonce = await labeledExpand(suite, secret, "base_nonce", context, 12);

  const aesKey = await crypto.subtle.importKey("raw", key as BufferSource, "AES-GCM", false, ["encrypt"]);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce as BufferSource, additionalData: (input.aad ?? new Uint8Array(0)) as BufferSource }, aesKey, input.plaintext as BufferSource));
  return concat(eph.publicRaw, ct);
}

export type RecipientKey = { privateKey: CryptoKey; publicRaw: Uint8Array };

/** importRecipient builds a recipient key from a JWK, as the gateway stores it. */
export async function importRecipient(jwk: JsonWebKey): Promise<RecipientKey> {
  const privateKey = await crypto.subtle.importKey("jwk", jwk, { name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
  const x = fromBase64Url(jwk.x ?? ""), y = fromBase64Url(jwk.y ?? "");
  if (x.length !== 32 || y.length !== 32) throw new Error("Invalid recipient key.");
  return { privateKey, publicRaw: concat(new Uint8Array([4]), x, y) };
}

/** open decrypts enc || ciphertext from seal, for a recipient such as the gateway. */
export async function open(recipient: RecipientKey, info: Uint8Array, sealed: Uint8Array, aad?: Uint8Array, aeadId?: number): Promise<Uint8Array> {
  const aead = aeadId ?? AEAD_AES256GCM;
  const nk = aead === AEAD_AES128GCM ? 16 : 32;
  if (sealed.length < 65 + 16) throw new Error("Ciphertext too short.");
  const enc = sealed.subarray(0, 65);
  const pkE = await importPublic(enc);
  const dh = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: pkE }, recipient.privateKey, 256));
  const kemSuite = concat(te.encode("KEM"), i2osp(KEM_P256, 2));
  const eaePrk = await labeledExtract(kemSuite, new Uint8Array(0), "eae_prk", dh);
  const shared = await labeledExpand(kemSuite, eaePrk, "shared_secret", concat(enc, recipient.publicRaw), NH);
  const suite = concat(te.encode("HPKE"), i2osp(KEM_P256, 2), i2osp(KDF_HKDF_SHA256, 2), i2osp(aead, 2));
  const pskIdHash = await labeledExtract(suite, new Uint8Array(0), "psk_id_hash", new Uint8Array(0));
  const infoHash = await labeledExtract(suite, new Uint8Array(0), "info_hash", info);
  const context = concat(new Uint8Array([0]), pskIdHash, infoHash);
  const secret = await labeledExtract(suite, shared, "secret", new Uint8Array(0));
  const key = await labeledExpand(suite, secret, "key", context, nk);
  const nonce = await labeledExpand(suite, secret, "base_nonce", context, 12);
  const aesKey = await crypto.subtle.importKey("raw", key as BufferSource, "AES-GCM", false, ["decrypt"]);
  return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce as BufferSource, additionalData: (aad ?? new Uint8Array(0)) as BufferSource }, aesKey, sealed.subarray(65) as BufferSource));
}

/** sealedInfo is the HPKE info string that binds a ciphertext to its request. */
export function sealedInfo(id: string, policyHash: string, expiresAt: number): Uint8Array {
  return te.encode(`secrethandoff sealed-request ${SEALED_VERSION}|${id}|${policyHash}|${expiresAt}`);
}

const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/** pairingCode is 65 bits of SHA-256("sh-pair v1" || public key), as "XXXXX-XXXX-XXXX". */
export async function pairingCode(publicKey: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", concat(te.encode("sh-pair v1"), publicKey) as BufferSource));
  // Read the first 65 bits as thirteen 5-bit groups, most significant first.
  let out = "";
  for (let group = 0; group < 13; group++) {
    let v = 0;
    for (let b = 0; b < 5; b++) {
      const bit = group * 5 + b;
      v = (v << 1) | ((digest[bit >> 3] >> (7 - (bit & 7))) & 1);
    }
    out += CROCKFORD[v];
  }
  return out.slice(0, 5) + "-" + out.slice(5, 9) + "-" + out.slice(9);
}

/** confirmationCode is 35 bits of SHA-256("sh-fill v1" || id || ciphertext), as "XXX-XXXX" (ADR 0011). */
export async function confirmationCode(id: string, ciphertext: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", concat(te.encode("sh-fill v1"), te.encode(id), ciphertext) as BufferSource));
  let out = "";
  for (let group = 0; group < 7; group++) {
    let v = 0;
    for (let b = 0; b < 5; b++) {
      const bit = group * 5 + b;
      v = (v << 1) | ((digest[bit >> 3] >> (7 - (bit & 7))) & 1);
    }
    out += CROCKFORD[v];
  }
  return out.slice(0, 3) + "-" + out.slice(3);
}

/** fillProof derives the fill proof from the fill secret in the link. */
export async function fillProof(fillSecret: Uint8Array): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey("raw", fillSecret as BufferSource, "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: te.encode("secrethandoff fill-proof v1") }, key, 256));
}

export async function sha256Base64Url(data: Uint8Array): Promise<string> {
  return toBase64Url(new Uint8Array(await crypto.subtle.digest("SHA-256", data as BufferSource)));
}

export type RequestLink = { publicKey: Uint8Array; fillSecret: Uint8Array; policyHash: string };

/** parseFragment reads "v1.<public key>.<fill secret>.<policy hash>". */
export function parseFragment(fragment: string): RequestLink | null {
  const m = fragment.match(/^v1\.([A-Za-z0-9_-]{87})\.([A-Za-z0-9_-]{43})\.([A-Za-z0-9_-]{43})$/);
  if (!m) return null;
  return { publicKey: fromBase64Url(m[1]), fillSecret: fromBase64Url(m[2]), policyHash: m[3] };
}
