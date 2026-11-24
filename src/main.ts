// Starts the gateway.
//   GATEWAY_MASTER_KEY=$(node -e "console.log(require('crypto').randomBytes(32).toString('base64'))") \
//   node src/main.ts --db gateway.db --prices examples/prices.json --port 8787
//
// First run with --add-tenant <id> prints a new gateway API key for that tenant.
import { readFileSync } from "node:fs";
import { Gateway } from "./gateway.ts";
import { createGatewayServer } from "./http.ts";
import { KeyVault, hashApiKey, newApiKey } from "./keys.ts";
import { Store } from "./store.ts";
import { MockProvider } from "./providers/mock.ts";
import { OpenAICompatibleProvider } from "./providers/openai-compatible.ts";

const arg = (f: string, d?: string) => {
  const i = process.argv.indexOf(f);
  return i >= 0 ? process.argv[i + 1] : d;
};
const master = process.env.GATEWAY_MASTER_KEY;
if (!master) {
  console.error("Set GATEWAY_MASTER_KEY to a base64-encoded 32-byte key.");
  process.exit(1);
}
const store = new Store(arg("--db", "gateway.db"));
const vault = new KeyVault(master);
const { _note, ...prices } = JSON.parse(readFileSync(arg("--prices", "examples/prices.json")!, "utf8"));

const newTenant = arg("--add-tenant");
if (newTenant) {
  const key = newApiKey();
  store.addTenant({
    id: newTenant,
    name: newTenant,
    apiKeyHash: hashApiKey(key),
    monthlyBudgetUsd: Number(arg("--budget", "10")),
    policy: { allowedModels: Object.keys(prices), maxInputTokens: 8000, maxOutputTokens: 2000, pii: "redact", blockInjection: true },
  });
  console.log(`tenant ${newTenant} created. API key (shown once): ${key}`);
  process.exit(0);
}

const gw = new Gateway({
  store,
  vault,
  prices,
  providers: { mock: new MockProvider(), openai: new OpenAICompatibleProvider(process.env.OPENAI_BASE_URL ?? "https://api.openai.com/v1") },
  audit: (e) => process.stderr.write(JSON.stringify({ at: new Date().toISOString(), ...e }) + "\n"),
});
const port = Number(arg("--port", "8787"));
// Optional admin API for the dashboard: set GATEWAY_ADMIN_TOKEN to enable it.
const adminToken = process.env.GATEWAY_ADMIN_TOKEN;
createGatewayServer(gw, store, vault, { prices, adminTokenHash: adminToken ? hashApiKey(adminToken) : undefined }).listen(port, () =>
  console.log(`gateway listening on http://localhost:${port}${adminToken ? " (admin API on)" : ""}`),
);
