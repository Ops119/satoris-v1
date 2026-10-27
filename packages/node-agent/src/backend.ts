import type { ChatCompletionRequest, ChatCompletionResponse } from "@satoris/sealed";

/** The model server running next to the agent inside the TEE (vLLM, SGLang, TGI, llama.cpp...). */
export interface InferenceBackend {
  chat(request: ChatCompletionRequest): Promise<ChatCompletionResponse>;
  models(): Promise<string[]>;
}

/** Any server exposing the OpenAI Chat Completions API on localhost. */
export class OpenAICompatibleBackend implements InferenceBackend {
  constructor(
    private readonly baseUrl: string,
    private readonly apiKey?: string,
  ) {}

  private headers(): Record<string, string> {
    const h: Record<string, string> = { "content-type": "application/json" };
    if (this.apiKey) h.authorization = `Bearer ${this.apiKey}`;
    return h;
  }

  async chat(request: ChatCompletionRequest): Promise<ChatCompletionResponse> {
    const res = await fetch(`${this.baseUrl}/v1/chat/completions`, {
      method: "POST",
      headers: this.headers(),
      body: JSON.stringify({ ...request, stream: false }),
    });
    if (!res.ok) throw new BackendError(res.status, await res.text());
    return (await res.json()) as ChatCompletionResponse;
  }

  async models(): Promise<string[]> {
    const res = await fetch(`${this.baseUrl}/v1/models`, { headers: this.headers() });
    if (!res.ok) throw new BackendError(res.status, await res.text());
    const body = (await res.json()) as { data: Array<{ id: string }> };
    return body.data.map((m) => m.id);
  }
}

/** Deterministic backend for development and tests. Echoes the last user message. */
export class EchoBackend implements InferenceBackend {
  constructor(private readonly modelIds: string[] = ["echo-1"]) {}

  async chat(request: ChatCompletionRequest): Promise<ChatCompletionResponse> {
    const last = [...request.messages].reverse().find((m) => m.role === "user");
    const text = typeof last?.content === "string" ? last.content : JSON.stringify(last?.content ?? "");
    const limit = request.max_completion_tokens ?? request.max_tokens ?? 256;
    const words = `echo: ${text}`.split(/\s+/).slice(0, limit);
    const promptTokens = request.messages.reduce(
      (n, m) => n + (typeof m.content === "string" ? m.content.split(/\s+/).length : 0),
      0,
    );
    return {
      id: `chatcmpl-${crypto.randomUUID()}`,
      object: "chat.completion",
      created: Math.floor(Date.now() / 1000),
      model: request.model,
      choices: [
        {
          index: 0,
          message: { role: "assistant", content: words.join(" ") },
          finish_reason: words.length >= limit ? "length" : "stop",
        },
      ],
      usage: {
        prompt_tokens: promptTokens,
        completion_tokens: words.length,
        total_tokens: promptTokens + words.length,
      },
    };
  }

  async models(): Promise<string[]> {
    return this.modelIds;
  }
}

export class BackendError extends Error {
  constructor(
    readonly status: number,
    body: string,
  ) {
    super(`backend returned ${status}: ${body.slice(0, 200)}`);
  }
}
