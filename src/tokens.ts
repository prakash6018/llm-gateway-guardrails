// Fast token estimate without a tokenizer dependency. BPE tokenizers average
// roughly 4 characters per token for English; we take the larger of a
// character-based and a word-based estimate so dense text isn't undercounted.
// Good enough for budgeting; the provider's reported usage is what gets billed.
export function estimateTokens(text: string): number {
  if (!text) return 0;
  const byChars = Math.ceil(text.length / 4);
  const byWords = Math.ceil((text.match(/\S+/g)?.length ?? 0) * 1.3);
  return Math.max(byChars, byWords);
}

export interface ChatMessage {
  role: "system" | "user" | "assistant";
  content: string;
}

/** Each message carries a few tokens of framing on top of its content. */
export function estimateMessages(messages: ChatMessage[]): number {
  return messages.reduce((n, m) => n + 4 + estimateTokens(m.content), 3);
}
