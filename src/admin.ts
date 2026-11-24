// Admin API used by the dashboard. Guarded by a separate admin token that
// only the dashboard's server holds; it is never sent to a browser.
//
//   GET   /admin/tenants                    tenants with budget, spend and month stats
//   GET   /admin/tenants/:id                one tenant: daily series, usage by model, recent events, key hints
//   PATCH /admin/tenants/:id                change name, monthly budget or policy
//   POST  /admin/tenants/:id/estimate       policy check + cost prediction, no model call
import type { IncomingMessage } from "node:http";
import { Gateway, GatewayError } from "./gateway.ts";
import { hashApiKey, sameHash } from "./keys.ts";
import type { TenantPolicy } from "./policy.ts";
import type { PriceTable } from "./pricing.ts";
import { round } from "./pricing.ts";
import type { Store, Tenant } from "./store.ts";

export function validatePolicy(p: any, knownModels: string[]): TenantPolicy {
  const bad = (m: string) => new GatewayError(400, "bad_policy", m);
  if (typeof p !== "object" || p === null) throw bad("policy must be an object");
  if (!Array.isArray(p.allowedModels) || p.allowedModels.some((m: unknown) => typeof m !== "string" || !knownModels.includes(m as string)))
    throw bad(`allowedModels must be a list of: ${knownModels.join(", ")}`);
  for (const k of ["maxInputTokens", "maxOutputTokens"])
    if (!Number.isInteger(p[k]) || p[k] < 1 || p[k] > 1_000_000) throw bad(`${k} must be an integer from 1 to 1000000`);
  if (!["redact", "block", "allow"].includes(p.pii)) throw bad("pii must be redact, block or allow");
  if (typeof p.blockInjection !== "boolean") throw bad("blockInjection must be true or false");
  const terms = p.blockedTerms ?? [];
  if (!Array.isArray(terms) || terms.length > 100 || terms.some((t: unknown) => typeof t !== "string" || !t.trim() || t.length > 100))
    throw bad("blockedTerms must be up to 100 non-empty strings");
  return {
    allowedModels: [...new Set<string>(p.allowedModels)],
    maxInputTokens: p.maxInputTokens,
    maxOutputTokens: p.maxOutputTokens,
    pii: p.pii,
    blockInjection: p.blockInjection,
    blockedTerms: terms.map((t: string) => t.trim()),
  };
}

function summary(store: Store, t: Tenant) {
  const committed = store.committed(t.id);
  return {
    id: t.id,
    name: t.name,
    monthlyBudgetUsd: t.monthlyBudgetUsd,
    spentUsd: round(committed),
    policy: t.policy,
    ...store.monthStats(t.id),
  };
}

export async function handleAdmin(
  req: IncomingMessage,
  url: URL,
  readJson: () => Promise<any>,
  deps: { gw: Gateway; store: Store; prices: PriceTable; adminTokenHash: string },
): Promise<unknown> {
  const token = req.headers["x-admin-token"];
  if (typeof token !== "string" || !sameHash(hashApiKey(token), deps.adminTokenHash))
    throw new GatewayError(401, "unauthenticated", "admin token required");
  const { store, gw, prices } = deps;

  if (req.method === "GET" && url.pathname === "/admin/tenants")
    return { tenants: store.tenants().map((t) => summary(store, t)), models: Object.keys(prices) };

  const m = url.pathname.match(/^\/admin\/tenants\/([A-Za-z0-9_-]+)(\/estimate)?$/);
  if (!m) throw new GatewayError(404, "not_found", "no such route");
  const tenant = store.tenant(m[1]);
  if (!tenant) throw new GatewayError(404, "not_found", "no such tenant");

  if (m[2] && req.method === "POST") {
    const { estimate, budget, verdict } = gw.estimate(tenant, await readJson());
    return { estimate, budget, findings: verdict.findings, redacted: verdict.messages };
  }
  if (!m[2] && req.method === "GET") {
    const days = Math.min(90, Math.max(7, Number(url.searchParams.get("days") ?? 30) || 30));
    return {
      tenant: summary(store, tenant),
      daily: store.daily(tenant.id, days),
      byModel: store.usage(tenant.id).map((r) => ({ ...r })),
      events: store.recentEvents(tenant.id, 25),
      keys: store.providerKeyHints(tenant.id),
      models: Object.keys(prices),
    };
  }
  if (!m[2] && req.method === "PATCH") {
    const body = await readJson();
    const patch: { name?: string; monthlyBudgetUsd?: number; policy?: TenantPolicy } = {};
    if (body.name !== undefined) {
      if (typeof body.name !== "string" || !body.name.trim() || body.name.length > 80) throw new GatewayError(400, "bad_request", "name must be 1-80 characters");
      patch.name = body.name.trim();
    }
    if (body.monthlyBudgetUsd !== undefined) {
      if (typeof body.monthlyBudgetUsd !== "number" || !(body.monthlyBudgetUsd >= 0) || body.monthlyBudgetUsd > 1_000_000)
        throw new GatewayError(400, "bad_request", "monthlyBudgetUsd must be between 0 and 1000000");
      patch.monthlyBudgetUsd = body.monthlyBudgetUsd;
    }
    if (body.policy !== undefined) patch.policy = validatePolicy(body.policy, Object.keys(prices));
    const updated = store.updateTenant(tenant.id, patch)!;
    return { tenant: summary(store, updated) };
  }
  throw new GatewayError(405, "method_not_allowed", "method not allowed");
}
