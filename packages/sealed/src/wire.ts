/**
 * Wire types shared by client, gateway and node. Only the subset of the OpenAI
 * Chat Completions schema the gateway needs to understand is typed; everything
 * else passes through untouched.
 */
import type { SealedEnvelope, SealedMeta } from "./index.js";

export interface ChatMessage {
  role: "system" | "user" | "assistant" | "tool";
  content: string | Array<{ type: string; text?: string; [k: string]: unknown }> | null;
  [k: string]: unknown;
}

export interface ChatCompletionRequest {
  model: string;
  messages: ChatMessage[];
  max_tokens?: number;
  max_completion_tokens?: number;
  stream?: boolean;
  [k: string]: unknown;
}

export interface Usage {
  prompt_tokens: number;
  completion_tokens: number;
  total_tokens: number;
}

export interface ChatCompletionResponse {
  id: string;
  object: "chat.completion";
  created: number;
  model: string;
  choices: Array<{ index: number; message: ChatMessage; finish_reason: string | null }>;
  usage: Usage;
  [k: string]: unknown;
}

/** Body of POST /v1/sealed/chat/completions. */
export interface SealedChatRequest {
  meta: SealedMeta;
  /** Id of the node whose attested key the envelope was sealed to. */
  node: string;
  envelope: SealedEnvelope;
}

/** Response of the sealed endpoint: usage stays clear so the gateway can bill. */
export interface SealedChatResponse {
  usage: Usage;
  envelope: SealedEnvelope;
}
