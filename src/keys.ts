// Bring-your-own-key storage: each tenant's provider API key is encrypted at
// rest with AES-256-GCM. The master key comes from the environment (or a KMS
// in production) and never touches the database.
import { createCipheriv, createDecipheriv, createHash, randomBytes, timingSafeEqual } from "node:crypto";

export interface SealedKey {
  iv: string;
  tag: string;
  data: string;
  /** For display only, e.g. "…a1b2". */
  hint: string;
}

export class KeyVault {
  private master: Buffer;

  constructor(masterKeyBase64: string) {
    this.master = Buffer.from(masterKeyBase64, "base64");
    if (this.master.length !== 32) throw new Error("master key must be 32 bytes (base64)");
  }

  static generateMasterKey(): string {
    return randomBytes(32).toString("base64");
  }

  /** `aad` binds the ciphertext to one tenant+provider, so a row copied to another tenant won't decrypt. */
  seal(secret: string, aad: string): SealedKey {
    const iv = randomBytes(12);
    const c = createCipheriv("aes-256-gcm", this.master, iv);
    c.setAAD(Buffer.from(aad));
    const data = Buffer.concat([c.update(secret, "utf8"), c.final()]);
    return { iv: iv.toString("base64"), tag: c.getAuthTag().toString("base64"), data: data.toString("base64"), hint: "…" + secret.slice(-4) };
  }

  open(sealed: SealedKey, aad: string): string {
    const d = createDecipheriv("aes-256-gcm", this.master, Buffer.from(sealed.iv, "base64"));
    d.setAAD(Buffer.from(aad));
    d.setAuthTag(Buffer.from(sealed.tag, "base64"));
    return Buffer.concat([d.update(Buffer.from(sealed.data, "base64")), d.final()]).toString("utf8");
  }
}

/** Gateway API keys are stored only as SHA-256 hashes and compared in constant time. */
export const hashApiKey = (key: string) => createHash("sha256").update(key).digest("hex");

export function sameHash(a: string, b: string): boolean {
  const x = Buffer.from(a, "hex");
  const y = Buffer.from(b, "hex");
  return x.length === y.length && timingSafeEqual(x, y);
}

export const newApiKey = () => "gw_" + randomBytes(24).toString("base64url");
