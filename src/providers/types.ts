import type { ChatMessage } from "../tokens.ts";

export interface CompletionRequest {
  model: string;
  messages: ChatMessage[];
  maxTokens: number;
  apiKey: string;
  signal?: AbortSignal;
}

export interface CompletionResult {
  text: string;
  inputTokens: number;
  outputTokens: number;
}

export interface Provider {
  complete(req: CompletionRequest): Promise<CompletionResult>;
}
