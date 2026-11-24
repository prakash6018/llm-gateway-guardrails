// Request and response checks that run before any tokens are spent.
import type { ChatMessage } from "./tokens.ts";

export interface TenantPolicy {
  allowedModels: string[];
  maxInputTokens: number;
  maxOutputTokens: number;
  /** "redact" replaces PII before it leaves the gateway; "block" refuses the request. */
  pii: "redact" | "block" | "allow";
  /** Refuse prompts that look like attempts to override the system prompt. */
  blockInjection: boolean;
  /** Case-insensitive phrases this tenant never wants sent to a model. */
  blockedTerms?: string[];
}

export interface Finding {
  rule: string;
  detail: string;
}

export interface PolicyResult {
  allowed: boolean;
  messages: ChatMessage[];
  findings: Finding[];
  reason?: string;
}

// Luhn check so random 16-digit numbers (order ids) aren't treated as cards.
function luhn(digits: string): boolean {
  let sum = 0;
  for (let i = 0; i < digits.length; i++) {
    let d = Number(digits[digits.length - 1 - i]);
    if (i % 2 === 1) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
  }
  return sum % 10 === 0;
}

// Verhoeff check digit, which every Aadhaar number carries; filters out
// most 12-digit numbers that merely look like one.
const VD = [[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],[3,4,0,1,2,8,9,5,6,7],[4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],[6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],[8,7,6,5,9,3,2,1,0,4],[9,8,7,6,5,4,3,2,1,0]];
const VP = [[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],[8,9,1,6,0,4,3,5,2,7],[9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],[2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]];
export function verhoeff(digits: string): boolean {
  let c = 0;
  for (let i = 0; i < digits.length; i++) c = VD[c][VP[i % 8][Number(digits[digits.length - 1 - i])]];
  return c === 0;
}

interface Detector {
  rule: string;
  re: RegExp;
  label: string;
  accept?: (match: string) => boolean;
}

const DETECTORS: Detector[] = [
  { rule: "pii.email", re: /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, label: "[EMAIL]" },
  {
    rule: "pii.card",
    re: /\b\d(?:[ -]?\d){12,18}\b/g,
    label: "[CARD]",
    accept: (m) => {
      const d = m.replace(/\D/g, "");
      return d.length >= 13 && d.length <= 19 && luhn(d);
    },
  },
  { rule: "pii.pan", re: /\b[A-Z]{5}\d{4}[A-Z]\b/g, label: "[PAN]" },
  { rule: "pii.aadhaar", re: /\b[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}\b/g, label: "[AADHAAR]", accept: (m) => verhoeff(m.replace(/\D/g, "")) },
  { rule: "pii.phone", re: /(?:\+91[ -]?)?\b[6-9]\d{9}\b/g, label: "[PHONE]" },
  { rule: "secret.api_key", re: /\b(?:sk|rk|pk)[-_](?:live|test|proj)?[-_]?[A-Za-z0-9]{16,}\b/g, label: "[SECRET]" },
];

const INJECTION = [
  /ignore (?:all |any )?(?:the )?(?:previous|prior|above) (?:instructions|prompts?|rules)/i,
  /disregard (?:the |your )?(?:system|previous) (?:prompt|instructions)/i,
  /you are now (?:in )?(?:developer|dan|jailbreak) mode/i,
  /reveal (?:your |the )?(?:system prompt|hidden instructions)/i,
  /<\/?(?:system|im_start|im_end)>/i,
];

/** Find PII in text; returns the redacted text and what was found. */
export function scanPii(text: string): { text: string; findings: Finding[] } {
  const findings: Finding[] = [];
  let out = text;
  for (const d of DETECTORS) {
    out = out.replace(d.re, (m) => {
      if (d.accept && !d.accept(m)) return m;
      findings.push({ rule: d.rule, detail: d.label });
      return d.label;
    });
  }
  return { text: out, findings };
}

export function checkRequest(
  policy: TenantPolicy,
  model: string,
  messages: ChatMessage[],
  inputTokens: number,
  maxOutputTokens: number,
): PolicyResult {
  const deny = (rule: string, reason: string): PolicyResult => ({
    allowed: false,
    messages,
    findings: [{ rule, detail: reason }],
    reason,
  });
  if (!policy.allowedModels.includes(model)) return deny("model.not_allowed", `model ${model} is not enabled for this tenant`);
  if (inputTokens > policy.maxInputTokens)
    return deny("limits.input", `prompt is ~${inputTokens} tokens; limit is ${policy.maxInputTokens}`);
  if (maxOutputTokens > policy.maxOutputTokens)
    return deny("limits.output", `max_tokens ${maxOutputTokens} exceeds limit ${policy.maxOutputTokens}`);

  const findings: Finding[] = [];
  const out: ChatMessage[] = [];
  for (const m of messages) {
    const lower = m.content.toLowerCase();
    const term = policy.blockedTerms?.find((t) => lower.includes(t.toLowerCase()));
    if (term) return deny("content.blocked_term", `prompt contains a blocked term`);
    // Only user turns are checked for injection: system prompts are the tenant's own.
    if (policy.blockInjection && m.role === "user" && INJECTION.some((re) => re.test(m.content)))
      return deny("injection", "prompt looks like an attempt to override instructions");
    if (policy.pii === "allow") {
      out.push(m);
      continue;
    }
    const scan = scanPii(m.content);
    if (scan.findings.length && policy.pii === "block")
      return deny(scan.findings[0].rule, `prompt contains personal data (${scan.findings.map((f) => f.detail).join(", ")})`);
    findings.push(...scan.findings);
    out.push({ ...m, content: scan.text });
  }
  return { allowed: true, messages: out, findings };
}
