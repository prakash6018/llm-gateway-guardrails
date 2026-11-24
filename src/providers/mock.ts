// Deterministic provider for tests and the demo: no network, no key needed.
import { estimateMessages, estimateTokens } from "../tokens.ts";
import type { CompletionRequest, CompletionResult, Provider } from "./types.ts";

export class MockProvider implements Provider {
  calls: CompletionRequest[] = [];
  reply: (req: CompletionRequest) => string;

  constructor(reply?: (req: CompletionRequest) => string) {
    this.reply = reply ?? ((r) => `Echo: ${r.messages[r.messages.length - 1].content}`);
  }

  async complete(req: CompletionRequest): Promise<CompletionResult> {
    this.calls.push(req);
    const words = this.reply(req).split(" ");
    let text = "";
    for (const w of words) {
      const next = text ? `${text} ${w}` : w;
      if (estimateTokens(next) > req.maxTokens) break;
      text = next;
    }
    return { text, inputTokens: estimateMessages(req.messages), outputTokens: estimateTokens(text) };
  }
}
