// Per-model prices in USD per million tokens. The numbers in examples/ are
// placeholders: load real prices from config, since providers change them.
export interface ModelPrice {
  provider: string;
  inputPerMTok: number;
  outputPerMTok: number;
  contextWindow: number;
}

export type PriceTable = Record<string, ModelPrice>;

export interface CostEstimate {
  model: string;
  inputTokens: number;
  maxOutputTokens: number;
  /** Cost if the model uses every output token allowed: what we reserve. */
  worstCaseUsd: number;
  /** Cost if the reply is about as long as typical (a quarter of the cap). */
  likelyUsd: number;
}

export const usd = (tokens: number, perMTok: number) => (tokens * perMTok) / 1_000_000;

export function predictCost(prices: PriceTable, model: string, inputTokens: number, maxOutputTokens: number): CostEstimate {
  const p = prices[model];
  if (!p) throw new Error(`unknown model: ${model}`);
  const inCost = usd(inputTokens, p.inputPerMTok);
  return {
    model,
    inputTokens,
    maxOutputTokens,
    worstCaseUsd: round(inCost + usd(maxOutputTokens, p.outputPerMTok)),
    likelyUsd: round(inCost + usd(Math.ceil(maxOutputTokens / 4), p.outputPerMTok)),
  };
}

export const round = (x: number) => Math.round(x * 1e6) / 1e6;
