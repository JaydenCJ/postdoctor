import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import { parseDkimRecord, parseTagValueList, rsaKeyBits } from "../src/dkim/record.js";

/** Generate a real RSA public key in the base64 SPKI form DKIM uses. */
function rsaPublicKeyBase64(modulusLength: number): string {
  const { publicKey } = generateKeyPairSync("rsa", { modulusLength });
  return publicKey.export({ type: "spki", format: "der" }).toString("base64");
}

describe("parseTagValueList", () => {
  it("parses tags and trims whitespace", () => {
    const { tags, errors } = parseTagValueList(" v=DKIM1 ; k=rsa;  p=abc ");
    expect(errors).toEqual([]);
    expect(tags).toEqual({ v: "DKIM1", k: "rsa", p: "abc" });
  });

  it("flags duplicate tags and malformed items", () => {
    const { errors } = parseTagValueList("v=DKIM1; v=DKIM1; oops");
    expect(errors.some((e) => e.includes("duplicate"))).toBe(true);
    expect(errors.some((e) => e.includes('missing "="'))).toBe(true);
  });

  it("allows values containing = (base64 padding)", () => {
    const { tags } = parseTagValueList("p=AAAA==");
    expect(tags["p"]).toBe("AAAA==");
  });
});

describe("rsaKeyBits", () => {
  it("measures a 2048-bit key", () => {
    expect(rsaKeyBits(rsaPublicKeyBase64(2048))).toBe(2048);
  });

  it("measures a 1024-bit key", () => {
    expect(rsaKeyBits(rsaPublicKeyBase64(1024))).toBe(1024);
  });

  it("returns undefined for garbage input", () => {
    expect(rsaKeyBits("aGVsbG8gd29ybGQ=")).toBeUndefined();
    expect(rsaKeyBits("")).toBeUndefined();
  });
});

describe("parseDkimRecord", () => {
  it("accepts a healthy 2048-bit record", () => {
    const rec = parseDkimRecord(`v=DKIM1; k=rsa; p=${rsaPublicKeyBase64(2048)}`);
    expect(rec.errors).toEqual([]);
    expect(rec.keyType).toBe("rsa");
    expect(rec.keyBits).toBe(2048);
    expect(rec.revoked).toBe(false);
    expect(rec.testing).toBe(false);
  });

  it("treats an empty p= as a revoked key", () => {
    const rec = parseDkimRecord("v=DKIM1; k=rsa; p=");
    expect(rec.revoked).toBe(true);
    expect(rec.errors).toEqual([]);
  });

  it("requires the p= tag", () => {
    const rec = parseDkimRecord("v=DKIM1; k=rsa");
    expect(rec.errors.some((e) => e.includes("p="))).toBe(true);
  });

  it("detects testing mode from t=y and t=y:s", () => {
    const key = rsaPublicKeyBase64(2048);
    expect(parseDkimRecord(`v=DKIM1; t=y; p=${key}`).testing).toBe(true);
    expect(parseDkimRecord(`v=DKIM1; t=y:s; p=${key}`).testing).toBe(true);
    expect(parseDkimRecord(`v=DKIM1; t=s; p=${key}`).testing).toBe(false);
  });

  it("rejects invalid base64 in p=", () => {
    const rec = parseDkimRecord("v=DKIM1; p=!!!notbase64!!!");
    expect(rec.errors.some((e) => e.includes("base64"))).toBe(true);
  });

  it("rejects a p= that is base64 but not an RSA key", () => {
    const rec = parseDkimRecord(`v=DKIM1; k=rsa; p=${Buffer.from("plain text, not DER").toString("base64")}`);
    expect(rec.errors.some((e) => e.includes("SubjectPublicKeyInfo"))).toBe(true);
  });

  it("validates ed25519 key length", () => {
    const good = Buffer.alloc(32, 7).toString("base64");
    const bad = Buffer.alloc(16, 7).toString("base64");
    expect(parseDkimRecord(`v=DKIM1; k=ed25519; p=${good}`).errors).toEqual([]);
    expect(
      parseDkimRecord(`v=DKIM1; k=ed25519; p=${bad}`).errors.some((e) => e.includes("32")),
    ).toBe(true);
  });

  it("flags unknown key types and wrong v=", () => {
    expect(parseDkimRecord("v=DKIM2; p=AAAA").errors.some((e) => e.includes("DKIM1"))).toBe(true);
    expect(
      parseDkimRecord("v=DKIM1; k=dsa; p=AAAA").errors.some((e) => e.includes("unknown key type")),
    ).toBe(true);
  });
});
