import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import type {
  AuditTarget,
  PromptSpec,
  ResourceSpec,
  ToolSpec,
  TransportKind,
} from "../types.js";

const CLIENT_INFO = { name: "mcp-audit", version: "0.1.0" };

/**
 * Connect a {@link Client} over an already-constructed transport, enumerate the
 * server's tools/resources/prompts, and return a normalized {@link AuditTarget}.
 * Capabilities the server does not advertise are treated as empty rather than
 * an error.
 */
export async function probe(
  transport: Transport,
  meta: {
    kind: TransportKind;
    source: string;
    url?: string;
    authProvided?: boolean;
  },
): Promise<AuditTarget> {
  const client = new Client(CLIENT_INFO, {
    capabilities: {},
  });

  await client.connect(transport);
  try {
    const version = client.getServerVersion();
    const instructions = client.getInstructions();

    const tools = await safeList(async () => {
      const res = await client.listTools();
      return res.tools as ToolSpec[];
    });
    const resources = await safeList(async () => {
      const res = await client.listResources();
      return res.resources as ResourceSpec[];
    });
    const prompts = await safeList(async () => {
      const res = await client.listPrompts();
      return res.prompts as PromptSpec[];
    });

    return {
      transport: meta.kind,
      source: meta.source,
      serverInfo: {
        name: version?.name,
        version: version?.version,
        instructions,
      },
      tools,
      resources,
      prompts,
      connection: { url: meta.url, authProvided: meta.authProvided },
    };
  } finally {
    await client.close().catch(() => undefined);
  }
}

/**
 * List a capability, returning an empty array when the server does not support
 * it (the SDK throws a "Method not found" error in that case).
 */
async function safeList<T>(fn: () => Promise<T[]>): Promise<T[]> {
  try {
    return await fn();
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    if (/method not found|-32601|not supported|no such/i.test(message)) {
      return [];
    }
    throw err;
  }
}
