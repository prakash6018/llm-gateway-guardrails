// The request pipeline:
//
//   authenticate → policy (models, limits, injection, PII) → predict cost
//   → reserve budget → decrypt tenant key → call provider (timeout)
//   → scan output → settle actual cost → audit
//
// Every step that can refuse does so before any tokens are bought.
import { hashApiKey, sameHash, type KeyVault } from "./keys.ts";
import { checkRequest, scanPii, type Finding } from "./policy.ts";
import { predictCost, round, usd, type CostEstimate, type PriceTable } from "./pricing.ts";
import { BudgetExceeded, type Store, type Tenant } from "./store.ts";
import { estimateMessages, type ChatMessage } from "./tokens.ts";
import type { Provider } from "./providers/types.ts";

export interface ChatRequest {
  model: string;
  messages: ChatMessage[];
  max_tokens?: number;
}

export interface ChatResponse {
  text: string;
  usage: { inputTokens: number; outputTokens: number; costUsd: number };
  estimate: CostEstimate;
  findings: Finding[];
}

export class GatewayError extends Error {
  status: number;
  code: string;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

export interface GatewayOptions {
  store: Store;
  vault: KeyVault;
  prices: PriceTable;
  providers: Record<string, Provider>;
  timeoutMs?: number;
  audit?: (entry: Record<string, unknown>) => void;
}

export class Gateway {
  private o: GatewayOptions;

  constructor(o: GatewayOptions) {
    this.o = o;
  }

  authenticate(apiKey: string | undefined): Tenant {
    if (!apiKey) throw new GatewayError(401, "unauthenticated", "missing API key");
    const h = hashApiKey(apiKey);
    const t = this.o.store.tenants().find((t) => sameHash(t.apiKeyHash, h));
    if (!t) throw new GatewayError(401, "unauthenticated", "invalid API key");
    return t;
  }

  private validate(req: ChatRequest) {
    if (typeof req?.model !== "string" || !Array.isArray(req.messages) || req.messages.length === 0)
      throw new GatewayError(400, "bad_request", "model and a non-empty messages array are required");
    for (const m of req.messages)
      if (!["system", "user", "assistant"].includes(m?.role) || typeof m.content !== "string")
        throw new GatewayError(400, "bad_request", "each message needs a role and string content");
  }

  /** Policy check and cost prediction without calling a model. */
  estimate(tenant: Tenant, req: ChatRequest) {
    this.validate(req);
    const maxTokens = req.max_tokens ?? Math.min(1024, tenant.policy.maxOutputTokens);
    const inputTokens = estimateMessages(req.messages);
    const verdict = checkRequest(tenant.policy, req.model, req.messages, inputTokens, maxTokens);
    if (!verdict.allowed) throw new GatewayError(422, "policy_violation", verdict.reason!);
    if (!this.o.prices[req.model]) throw new GatewayError(400, "unknown_model", `no price configured for ${req.model}`);
    const estimate = predictCost(this.o.prices, req.model, estimateMessages(verdict.messages), maxTokens);
    const committed = this.o.store.committed(tenant.id);
    return {
      verdict,
      estimate,
      budget: {
        monthlyUsd: tenant.monthlyBudgetUsd,
        committedUsd: round(committed),
        remainingUsd: round(tenant.monthlyBudgetUsd - committed),
        fits: committed + estimate.worstCaseUsd <= tenant.monthlyBudgetUsd,
      },
    };
  }

  async chat(tenant: Tenant, req: ChatRequest): Promise<ChatResponse> {
    const started = Date.now();
    const audit = (ok: boolean, extra: Record<string, unknown>) =>
      this.o.audit?.({ tenant: tenant.id, model: req?.model, ok, ms: Date.now() - started, ...extra });
    const record = (outcome: "ok" | "blocked" | "budget" | "error", code: string | null, r: Partial<{ inputTokens: number; outputTokens: number; costUsd: number; findings: string[] }> = {}) =>
      this.o.store.recordEvent({
        tenantId: tenant.id,
        model: typeof req?.model === "string" ? req.model : "",
        outcome,
        code,
        inputTokens: r.inputTokens ?? 0,
        outputTokens: r.outputTokens ?? 0,
        costUsd: r.costUsd ?? 0,
        findings: r.findings ?? [],
      });
    let reservation: string | undefined;
    try {
      const { verdict, estimate } = this.estimate(tenant, req);
      const price = this.o.prices[req.model];
      const provider = this.o.providers[price.provider];
      if (!provider) throw new GatewayError(500, "no_provider", `provider ${price.provider} is not configured`);
      const sealed = this.o.store.providerKey(tenant.id, price.provider);
      if (!sealed) throw new GatewayError(412, "no_key", `add your ${price.provider} API key first`);

      try {
        reservation = this.o.store.reserve(tenant.id, req.model, estimate.worstCaseUsd, tenant.monthlyBudgetUsd);
      } catch (e) {
        if (e instanceof BudgetExceeded) throw new GatewayError(402, "budget_exceeded", e.message);
        throw e;
      }

      const apiKey = this.o.vault.open(sealed, `${tenant.id}:${price.provider}`);
      const result = await provider.complete({
        model: req.model,
        messages: verdict.messages,
        maxTokens: estimate.maxOutputTokens,
        apiKey,
        signal: AbortSignal.timeout(this.o.timeoutMs ?? 60_000),
      });

      // Models can echo or invent personal data; scan the reply too.
      const outScan = tenant.policy.pii === "allow" ? { text: result.text, findings: [] } : scanPii(result.text);
      const costUsd = round(usd(result.inputTokens, price.inputPerMTok) + usd(result.outputTokens, price.outputPerMTok));
      this.o.store.settle(reservation, result.inputTokens, result.outputTokens, costUsd);
      const findings = [...verdict.findings, ...outScan.findings.map((f) => ({ ...f, rule: "output." + f.rule }))];
      record("ok", null, { inputTokens: result.inputTokens, outputTokens: result.outputTokens, costUsd, findings: findings.map((f) => f.rule) });
      audit(true, {
        inputTokens: result.inputTokens,
        outputTokens: result.outputTokens,
        costUsd,
        reservedUsd: estimate.worstCaseUsd,
        findings: findings.map((f) => f.rule),
      });
      return { text: outScan.text, usage: { inputTokens: result.inputTokens, outputTokens: result.outputTokens, costUsd }, estimate, findings };
    } catch (e) {
      if (reservation) this.o.store.release(reservation);
      const err =
        e instanceof GatewayError
          ? e
          : new GatewayError(502, "provider_error", (e as Error).name === "TimeoutError" ? "the model took too long" : "the model call failed");
      record(err.status === 402 ? "budget" : err.status >= 500 ? "error" : "blocked", err.code);
      audit(false, { code: err.code, error: err.message });
      throw err;
    }
  }
}
