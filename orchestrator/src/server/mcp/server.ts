/**
 * MCP server using StreamableHTTPServerTransport.
 *
 * Creates a new McpServer instance per session to avoid transport conflicts.
 * Validates Bearer tokens from the OAuth provider.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import type { Request, Response } from "express";
import { Router } from "express";
import { validateBearerToken } from "./oauth";
import { registerTools } from "./tools";

interface SessionEntry {
  transport: StreamableHTTPServerTransport;
  server: McpServer;
}

// Map of session ID -> { transport, server }
const sessions = new Map<string, SessionEntry>();

function createSessionServer(): McpServer {
  const server = new McpServer({
    name: "job-ops",
    version: "0.2.0",
  });
  registerTools(server);
  return server;
}

export function createMcpRouter(): Router {
  const router = Router();

  router.post("/mcp", async (req: Request, res: Response) => {
    if (!validateBearerToken(req.headers.authorization)) {
      res.status(401).json({ error: "Unauthorized" });
      return;
    }

    const sessionId = req.headers["mcp-session-id"] as string | undefined;

    const existing = sessionId ? sessions.get(sessionId) : undefined;
    if (sessionId && existing) {
      await existing.transport.handleRequest(req, res, req.body);
      return;
    }

    if (sessionId && !existing) {
      res.status(404).json({ error: "Session not found" });
      return;
    }

    // New session
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => crypto.randomUUID(),
    });
    const server = createSessionServer();

    transport.onclose = () => {
      if (transport.sessionId) {
        sessions.delete(transport.sessionId);
      }
    };

    await server.connect(transport);

    if (transport.sessionId) {
      sessions.set(transport.sessionId, { transport, server });
    }

    await transport.handleRequest(req, res, req.body);
  });

  // Handle GET for SSE streams (session resumption)
  router.get("/mcp", async (req: Request, res: Response) => {
    if (!validateBearerToken(req.headers.authorization)) {
      res.status(401).json({ error: "Unauthorized" });
      return;
    }

    const sessionId = req.headers["mcp-session-id"] as string | undefined;
    const entry = sessionId ? sessions.get(sessionId) : undefined;
    if (!entry) {
      res.status(404).json({ error: "Session not found" });
      return;
    }
    await entry.transport.handleRequest(req, res);
  });

  // Handle DELETE for session termination
  router.delete("/mcp", async (req: Request, res: Response) => {
    if (!validateBearerToken(req.headers.authorization)) {
      res.status(401).json({ error: "Unauthorized" });
      return;
    }

    const sessionId = req.headers["mcp-session-id"] as string | undefined;
    const entry = sessionId ? sessions.get(sessionId) : undefined;
    if (!entry) {
      res.status(404).json({ error: "Session not found" });
      return;
    }
    await entry.transport.close();
    if (sessionId) sessions.delete(sessionId);
    res.status(200).end();
  });

  return router;
}
