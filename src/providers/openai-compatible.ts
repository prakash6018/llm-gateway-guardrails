// Any provider exposing an OpenAI-style /chat/completions endpoint
// (OpenAI, Azure OpenAI, Groq, Together, local vLLM/Ollama, ...).
import type { CompletionRequest, CompletionResult, Provider } from "./types.ts";

export class OpenAICompatibleProvider implements Provider {
  private baseUrl: string;

  constructor(baseUrl: string) {
    this.baseUrl = baseUrl.replace(/\/$/, "");
  }

  async complete(req: CompletionRequest): Promise<CompletionResult> {
    const res = await fetch(`${this.baseUrl}/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${req.apiKey}` },
      body: JSON.stringify({ model: req.model, messages: req.messages, max_tokens: req.maxTokens }),
      signal: req.signal,
    });
    if (!res.ok) throw new Error(`provider returned HTTP ${res.status}`);
    const body: any = await res.json();
    return {
      text: body.choices?.[0]?.message?.content ?? "",
      inputTokens: body.usage?.prompt_tokens ?? 0,
      outputTokens: body.usage?.completion_tokens ?? 0,
    };
  }
}
