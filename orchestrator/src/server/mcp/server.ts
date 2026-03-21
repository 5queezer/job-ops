/**
 * MCP server using StreamableHTTPServerTransport.
 *
 * Exposes an Express router that handles POST /mcp requests,
 * validating Bearer tokens from the OAuth provider.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import type { Request, Response } from "express";
import { Router } from "express";
import { validateBearerToken } from "./oauth";
import { registerTools } from "./tools";

const mcpServer = new McpServer({
  name: "job-ops",
  version: "0.2.0",
});

registerTools(mcpServer);

// Map of session ID -> transport for stateful sessions
const transports = new Map<string, StreamableHTTPServerTransport>();

export function createMcpRouter(): Router {
  const router = Router();

  router.post("/mcp", async (req: Request, res: Response) => {
    if (!validateBearerToken(req.headers.authorization)) {
      res.status(401).json({ error: "Unauthorized" });
      return;
    }

    // Check for existing session
    const sessionId = req.headers["mcp-session-id"] as string | undefined;
    let transport: StreamableHTTPServerTransport;

    const existing = sessionId ? transports.get(sessionId) : undefined;
    if (sessionId && existing) {
      transport = existing;
    } else if (!sessionId) {
      // New session - create transport
      transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => crypto.randomUUID(),
      });

      transport.onclose = () => {
        if (transport.sessionId) {
          transports.delete(transport.sessionId);
        }
      };

      await mcpServer.connect(transport);

      if (transport.sessionId) {
        transports.set(transport.sessionId, transport);
      }
    } else {
      // Invalid session ID
      res.status(404).json({ error: "Session not found" });
      return;
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
    if (!sessionId || !transports.has(sessionId)) {
      res.status(404).json({ error: "Session not found" });
      return;
    }

    const transport = transports.get(sessionId);
    if (!transport) {
      res.status(404).json({ error: "Session not found" });
      return;
    }
    await transport.handleRequest(req, res);
  });

  // Handle DELETE for session termination
  router.delete("/mcp", async (req: Request, res: Response) => {
    if (!validateBearerToken(req.headers.authorization)) {
      res.status(401).json({ error: "Unauthorized" });
      return;
    }

    const sessionId = req.headers["mcp-session-id"] as string | undefined;
    if (!sessionId || !transports.has(sessionId)) {
      res.status(404).json({ error: "Session not found" });
      return;
    }

    const transport = transports.get(sessionId);
    if (!transport) {
      res.status(404).json({ error: "Session not found" });
      return;
    }
    await transport.close();
    transports.delete(sessionId);
    res.status(200).end();
  });

  return router;
}
