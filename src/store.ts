// Tenants, sealed provider keys and the usage ledger, in SQLite (node:sqlite).
//
// Budgets use reserve-then-settle: before calling a model we reserve the
// worst-case cost inside a transaction, so concurrent requests can't overspend
// a budget between "check" and "charge". After the call the reservation is
// replaced by the actual cost.
import { DatabaseSync } from "node:sqlite";
import { randomUUID } from "node:crypto";
import type { SealedKey } from "./keys.ts";
import type { TenantPolicy } from "./policy.ts";

export interface Tenant {
  id: string;
  name: string;
  apiKeyHash: string;
  monthlyBudgetUsd: number;
  policy: TenantPolicy;
}

export interface UsageRow {
  model: string;
  requests: number;
  inputTokens: number;
  outputTokens: number;
  costUsd: number;
}

export class BudgetExceeded extends Error {}

export type Outcome = "ok" | "blocked" | "budget" | "error";

export interface GatewayEvent {
  id: string;
  tenantId: string;
  at: string;
  model: string;
  outcome: Outcome;
  code: string | null;
  inputTokens: number;
  outputTokens: number;
  costUsd: number;
  findings: string[];
}

export interface DailyPoint {
  day: string;
  requests: number;
  blocked: number;
  costUsd: number;
}

const month = (d: Date) => d.toISOString().slice(0, 7);

export class Store {
  private db: DatabaseSync;
  /** Injectable clock so demo data can be generated for past days. */
  now: () => Date = () => new Date();

  constructor(path = ":memory:") {
    this.db = new DatabaseSync(path);
    this.db.exec(`
      PRAGMA journal_mode = WAL;
      CREATE TABLE IF NOT EXISTS tenants (
        id TEXT PRIMARY KEY, name TEXT NOT NULL, api_key_hash TEXT NOT NULL UNIQUE,
        monthly_budget_usd REAL NOT NULL, policy TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS provider_keys (
        tenant_id TEXT NOT NULL REFERENCES tenants(id), provider TEXT NOT NULL,
        sealed TEXT NOT NULL, created_at TEXT NOT NULL, PRIMARY KEY (tenant_id, provider));
      CREATE TABLE IF NOT EXISTS ledger (
        id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, month TEXT NOT NULL, model TEXT NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('reserved','settled','failed')),
        input_tokens INTEGER NOT NULL DEFAULT 0, output_tokens INTEGER NOT NULL DEFAULT 0,
        cost_usd REAL NOT NULL, created_at TEXT NOT NULL);
      CREATE INDEX IF NOT EXISTS ledger_tenant_month ON ledger (tenant_id, month);
      CREATE TABLE IF NOT EXISTS events (
        id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, at TEXT NOT NULL, model TEXT NOT NULL,
        outcome TEXT NOT NULL, code TEXT, input_tokens INTEGER NOT NULL, output_tokens INTEGER NOT NULL,
        cost_usd REAL NOT NULL, findings TEXT NOT NULL);
      CREATE INDEX IF NOT EXISTS events_tenant_at ON events (tenant_id, at);
    `);
  }

  addTenant(t: Tenant): void {
    this.db
      .prepare("INSERT INTO tenants VALUES (?, ?, ?, ?, ?)")
      .run(t.id, t.name, t.apiKeyHash, t.monthlyBudgetUsd, JSON.stringify(t.policy));
  }

  tenants(): Tenant[] {
    return this.db.prepare("SELECT * FROM tenants ORDER BY name").all().map((r: any) => ({
      id: r.id,
      name: r.name,
      apiKeyHash: r.api_key_hash,
      monthlyBudgetUsd: r.monthly_budget_usd,
      policy: JSON.parse(r.policy),
    }));
  }

  tenant(id: string): Tenant | undefined {
    return this.tenants().find((t) => t.id === id);
  }

  updateTenant(id: string, patch: { monthlyBudgetUsd?: number; policy?: TenantPolicy; name?: string }): Tenant | undefined {
    const t = this.tenant(id);
    if (!t) return undefined;
    const next = { ...t, ...patch };
    this.db
      .prepare("UPDATE tenants SET name = ?, monthly_budget_usd = ?, policy = ? WHERE id = ?")
      .run(next.name, next.monthlyBudgetUsd, JSON.stringify(next.policy), id);
    return next;
  }

  /** Providers this tenant has a key for (never the keys themselves). */
  providerKeyHints(tenantId: string): { provider: string; hint: string; createdAt: string }[] {
    return this.db
      .prepare("SELECT provider, sealed, created_at FROM provider_keys WHERE tenant_id = ? ORDER BY provider")
      .all(tenantId)
      .map((r: any) => ({ provider: r.provider, hint: JSON.parse(r.sealed).hint, createdAt: r.created_at }));
  }

  putProviderKey(tenantId: string, provider: string, sealed: SealedKey): void {
    this.db
      .prepare("INSERT OR REPLACE INTO provider_keys VALUES (?, ?, ?, ?)")
      .run(tenantId, provider, JSON.stringify(sealed), this.now().toISOString());
  }

  providerKey(tenantId: string, provider: string): SealedKey | undefined {
    const r = this.db.prepare("SELECT sealed FROM provider_keys WHERE tenant_id = ? AND provider = ?").get(tenantId, provider) as
      | { sealed: string }
      | undefined;
    return r ? JSON.parse(r.sealed) : undefined;
  }

  /** Money committed this month: settled costs plus open reservations. */
  committed(tenantId: string): number {
    const r = this.db
      .prepare("SELECT COALESCE(SUM(cost_usd), 0) AS c FROM ledger WHERE tenant_id = ? AND month = ? AND status != 'failed'")
      .get(tenantId, month(this.now())) as { c: number };
    return r.c;
  }

  reserve(tenantId: string, model: string, amountUsd: number, budgetUsd: number): string {
    const id = randomUUID();
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const used = this.committed(tenantId);
      if (used + amountUsd > budgetUsd) {
        throw new BudgetExceeded(
          `monthly budget $${budgetUsd} would be exceeded: $${used.toFixed(4)} committed, this request may cost up to $${amountUsd.toFixed(4)}`,
        );
      }
      this.db
        .prepare("INSERT INTO ledger (id, tenant_id, month, model, status, cost_usd, created_at) VALUES (?, ?, ?, ?, 'reserved', ?, ?)")
        .run(id, tenantId, month(this.now()), model, amountUsd, this.now().toISOString());
      this.db.exec("COMMIT");
      return id;
    } catch (e) {
      this.db.exec("ROLLBACK");
      throw e;
    }
  }

  settle(id: string, inputTokens: number, outputTokens: number, costUsd: number): void {
    this.db
      .prepare("UPDATE ledger SET status = 'settled', input_tokens = ?, output_tokens = ?, cost_usd = ? WHERE id = ? AND status = 'reserved'")
      .run(inputTokens, outputTokens, costUsd, id);
  }

  release(id: string): void {
    this.db.prepare("UPDATE ledger SET status = 'failed', cost_usd = 0 WHERE id = ? AND status = 'reserved'").run(id);
  }

  usage(tenantId: string, m = month(this.now())): UsageRow[] {
    return this.db
      .prepare(
        `SELECT model, COUNT(*) AS requests, SUM(input_tokens) AS inputTokens, SUM(output_tokens) AS outputTokens,
                ROUND(SUM(cost_usd), 6) AS costUsd
         FROM ledger WHERE tenant_id = ? AND month = ? AND status = 'settled' GROUP BY model ORDER BY costUsd DESC`,
      )
      .all(tenantId, m) as unknown as UsageRow[];
  }

  recordEvent(e: Omit<GatewayEvent, "id" | "at">): void {
    this.db
      .prepare("INSERT INTO events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
      .run(randomUUID(), e.tenantId, this.now().toISOString(), e.model ?? "", e.outcome, e.code, e.inputTokens, e.outputTokens, e.costUsd, JSON.stringify(e.findings));
  }

  recentEvents(tenantId: string, limit = 50): GatewayEvent[] {
    return this.db
      .prepare("SELECT * FROM events WHERE tenant_id = ? ORDER BY at DESC LIMIT ?")
      .all(tenantId, limit)
      .map((r: any) => ({
        id: r.id,
        tenantId: r.tenant_id,
        at: r.at,
        model: r.model,
        outcome: r.outcome,
        code: r.code,
        inputTokens: r.input_tokens,
        outputTokens: r.output_tokens,
        costUsd: r.cost_usd,
        findings: JSON.parse(r.findings),
      }));
  }

  /** One point per day for the last `days` days, zero-filled. */
  daily(tenantId: string, days = 30): DailyPoint[] {
    const end = this.now();
    const start = new Date(end.getTime() - (days - 1) * 86_400_000);
    const rows = this.db
      .prepare(
        `SELECT substr(at, 1, 10) AS day, COUNT(*) AS requests,
                SUM(outcome != 'ok') AS blocked, ROUND(SUM(cost_usd), 6) AS costUsd
         FROM events WHERE tenant_id = ? AND at >= ? GROUP BY day`,
      )
      .all(tenantId, start.toISOString().slice(0, 10)) as any[];
    const byDay = new Map(rows.map((r) => [r.day, r]));
    return Array.from({ length: days }, (_, i) => {
      const day = new Date(start.getTime() + i * 86_400_000).toISOString().slice(0, 10);
      const r = byDay.get(day);
      return { day, requests: r?.requests ?? 0, blocked: r?.blocked ?? 0, costUsd: r?.costUsd ?? 0 };
    });
  }

  /** Counts for the current month: requests, blocked, PII findings. */
  monthStats(tenantId: string): { requests: number; blocked: number; piiRedactions: number } {
    const r = this.db
      .prepare(
        `SELECT COUNT(*) AS requests, COALESCE(SUM(outcome != 'ok'), 0) AS blocked,
                COALESCE(SUM(findings LIKE '%pii.%'), 0) AS pii
         FROM events WHERE tenant_id = ? AND substr(at, 1, 7) = ?`,
      )
      .get(tenantId, month(this.now())) as any;
    return { requests: r.requests, blocked: r.blocked, piiRedactions: r.pii };
  }
}
