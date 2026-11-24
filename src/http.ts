// HTTP front end (node:http, no framework).
//
//   POST /v1/chat            run a chat completion through the guardrails
//   POST /v1/estimate        policy check + cost prediction, no model call
//   GET  /v1/usage           this month's metered usage for the caller
//   PUT  /v1/keys/:provider  store (BYOK) the caller's provider API key
import { createServer, type IncomingMessage, type Server } from "node:http";
import { Gateway, GatewayError } from "./gateway.ts";
import type { KeyVault } from "./keys.ts";
import type { Store } from "./store.ts";
import type { PriceTable } from "./pricing.ts";
import { handleAdmin } from "./admin.ts";

const MAX_BODY = 1_000_000;

async function readJson(req: IncomingMessage): Promise<any> {
  let size = 0;
  const chunks: Buffer[] = [];
  for await (const c of req) {
    size += c.length;
    if (size > MAX_BODY) throw new GatewayError(413, "too_large", "request body too large");
    chunks.push(c);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
  } catch {
    throw new GatewayError(400, "bad_json", "body is not valid JSON");
  }
}

export interface AdminOptions {
  prices: PriceTable;
  /** SHA-256 of the admin token (hashApiKey). Admin routes are off when absent. */
  adminTokenHash?: string;
}

export function createGatewayServer(gw: Gateway, store: Store, vault: KeyVault, admin?: AdminOptions): Server {
  return createServer(async (req, res) => {
    const send = (status: number, body: unknown) => {
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify(body));
    };
    try {
      if (req.url?.startsWith("/admin/")) {
        if (!admin?.adminTokenHash) throw new GatewayError(404, "not_found", "admin API is disabled");
        const url = new URL(req.url, "http://x");
        return send(200, await handleAdmin(req, url, () => readJson(req), { gw, store, prices: admin.prices, adminTokenHash: admin.adminTokenHash }));
      }
      const auth = req.headers.authorization?.replace(/^Bearer\s+/i, "");
      const tenant = gw.authenticate(auth);
      const url = new URL(req.url ?? "/", "http://x");
      if (req.method === "POST" && url.pathname === "/v1/chat") return send(200, await gw.chat(tenant, await readJson(req)));
      if (req.method === "POST" && url.pathname === "/v1/estimate") {
        const { estimate, budget, verdict } = gw.estimate(tenant, await readJson(req));
        return send(200, { estimate, budget, findings: verdict.findings });
      }
      if (req.method === "GET" && url.pathname === "/v1/usage")
        return send(200, { month: new Date().toISOString().slice(0, 7), budgetUsd: tenant.monthlyBudgetUsd, byModel: store.usage(tenant.id) });
      const keyRoute = url.pathname.match(/^\/v1\/keys\/([a-z0-9-]+)$/);
      if (req.method === "PUT" && keyRoute) {
        const { apiKey } = await readJson(req);
        if (typeof apiKey !== "string" || apiKey.length < 8) throw new GatewayError(400, "bad_request", "apiKey is required");
        const sealed = vault.seal(apiKey, `${tenant.id}:${keyRoute[1]}`);
        store.putProviderKey(tenant.id, keyRoute[1], sealed);
        return send(200, { provider: keyRoute[1], stored: true, hint: sealed.hint });
      }
      send(404, { error: { code: "not_found", message: "no such route" } });
    } catch (e) {
      const err = e instanceof GatewayError ? e : new GatewayError(500, "internal", "internal error");
      send(err.status, { error: { code: err.code, message: err.message } });
    }
  });
}
