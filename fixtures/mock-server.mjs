#!/usr/bin/env node
// A real MCP server over stdio, used as a hermetic test fixture. It serves one
// of the predefined surfaces so mcp-audit has a live server to connect to.
//
// Usage: node mock-server.mjs [insecure|clean]   (default: insecure)
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  ListToolsRequestSchema,
  ListResourcesRequestSchema,
  ListPromptsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { insecureSurface, cleanSurface } from "./surfaces.mjs";

const which = process.argv[2] ?? "insecure";
const surface = which === "clean" ? cleanSurface : insecureSurface;

const server = new Server(surface.serverInfo, {
  capabilities: { tools: {}, resources: {}, prompts: {} },
});

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: surface.tools,
}));
server.setRequestHandler(ListResourcesRequestSchema, async () => ({
  resources: surface.resources,
}));
server.setRequestHandler(ListPromptsRequestSchema, async () => ({
  prompts: surface.prompts,
}));

const transport = new StdioServerTransport();
await server.connect(transport);
