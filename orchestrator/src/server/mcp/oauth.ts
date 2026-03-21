/**
 * OAuth 2.1 provider with password-based login for remote MCP deployments.
 *
 * Implements the OAuth 2.1 authorization flow with:
 * - Dynamic Client Registration (DCR)
 * - PKCE (S256) support
 * - Password-based login page
 * - Rate limiting and security headers
 *
 * Ported from linkedin-mcp-server's Python PasswordOAuthProvider.
 */

import crypto from "node:crypto";
import type { Request, Response } from "express";
import { Router } from "express";

const AUTH_CODE_TTL_MS = 5 * 60 * 1000; // 5 minutes
const PENDING_REQUEST_TTL_MS = 10 * 60 * 1000; // 10 minutes
const MAX_FAILED_ATTEMPTS = 5;
const GLOBAL_MAX_FAILED_ATTEMPTS = 20;
const GLOBAL_RATE_LIMIT_WINDOW_MS = 5 * 60 * 1000; // 5 minutes
const GLOBAL_LOCKOUT_MS = 60 * 1000; // 60 seconds

const SECURITY_HEADERS: Record<string, string> = {
  "X-Frame-Options": "DENY",
  "Content-Security-Policy":
    "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'",
  "X-Content-Type-Options": "nosniff",
};

// ---------------------------------------------------------------------------
// In-memory stores
// ---------------------------------------------------------------------------

interface RegisteredClient {
  clientId: string;
  clientSecret: string;
  redirectUris: string[];
  clientName?: string;
  registeredAt: number;
}

interface AuthCode {
  code: string;
  clientId: string;
  redirectUri: string;
  scopes: string[];
  codeChallenge: string;
  expiresAt: number;
}

interface AccessToken {
  token: string;
  clientId: string;
  scopes: string[];
  createdAt: number;
}

interface PendingAuthRequest {
  clientId: string;
  redirectUri: string;
  state: string;
  codeChallenge: string;
  codeChallengeMethod: string;
  scopes: string[];
  createdAt: number;
  failedAttempts: number;
}

const clients = new Map<string, RegisteredClient>();
const authCodes = new Map<string, AuthCode>();
const accessTokens = new Map<string, AccessToken>();
const pendingRequests = new Map<string, PendingAuthRequest>();
const globalFailedAttempts: number[] = [];
let globalLockoutUntil = 0;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function getPassword(): string {
  const pw = process.env.MCP_OAUTH_PASSWORD;
  if (!pw) {
    throw new Error("MCP_OAUTH_PASSWORD environment variable is not set");
  }
  return pw;
}

function constantTimeCompare(a: string, b: string): boolean {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) {
    // Still do comparison to prevent timing side-channel on length
    crypto.timingSafeEqual(bufA, Buffer.alloc(bufA.length));
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

function htmlResponse(res: Response, html: string, status = 200): void {
  for (const [key, value] of Object.entries(SECURITY_HEADERS)) {
    res.setHeader(key, value);
  }
  res.status(status).type("text/html; charset=utf-8").send(html);
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#x27;");
}

function cleanupExpiredRequests(): void {
  const now = Date.now();
  for (const [id, req] of pendingRequests) {
    if (now - req.createdAt > PENDING_REQUEST_TTL_MS) {
      pendingRequests.delete(id);
    }
  }
}

function cleanupExpiredAuthCodes(): void {
  const now = Date.now();
  for (const [code, ac] of authCodes) {
    if (now > ac.expiresAt) {
      authCodes.delete(code);
    }
  }
}

function getBaseUrl(req: Request): string {
  if (process.env.PUBLIC_URL) {
    return process.env.PUBLIC_URL.replace(/\/+$/, "");
  }
  const proto = req.get("x-forwarded-proto") || req.protocol;
  const host = req.get("x-forwarded-host") || req.get("host");
  return `${proto}://${host}`;
}

function verifyCodeChallenge(
  codeVerifier: string,
  codeChallenge: string,
): boolean {
  const hash = crypto
    .createHash("sha256")
    .update(codeVerifier)
    .digest("base64url");
  return constantTimeCompare(hash, codeChallenge);
}

function loginHtml(requestId: string, error = ""): string {
  const errorHtml = error
    ? `<p style="color:#dc2626">${escapeHtml(error)}</p>`
    : "";
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Job Ops MCP Server &mdash; Login</title>
<style>
  body { font-family: system-ui, sans-serif; display: flex; justify-content: center;
         align-items: center; min-height: 100vh; margin: 0; background: #f5f5f5; }
  .card { background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,.1);
           max-width: 400px; width: 100%; }
  h1 { font-size: 1.25rem; margin: 0 0 1.5rem; }
  input[type=password] { width: 100%; padding: .5rem; margin: .5rem 0 1rem; box-sizing: border-box;
                          border: 1px solid #ccc; border-radius: 4px; font-size: 1rem; }
  button { width: 100%; padding: .6rem; background: #0a66c2; color: white; border: none;
            border-radius: 4px; font-size: 1rem; cursor: pointer; }
  button:hover { background: #004182; }
</style>
</head>
<body>
<div class="card">
  <h1>Job Ops MCP Server</h1>
  <p>Enter the server password to authorize this connection.</p>
  ${errorHtml}
  <form method="POST" action="/oauth/login">
    <input type="hidden" name="request_id" value="${escapeHtml(requestId)}">
    <label for="password">Password</label>
    <input type="password" id="password" name="password" required autofocus>
    <button type="submit">Authorize</button>
  </form>
</div>
</body>
</html>`;
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

export function createOAuthRouter(): Router {
  const router = Router();

  // OAuth Authorization Server Metadata
  router.get(
    "/.well-known/oauth-authorization-server",
    (req: Request, res: Response) => {
      const base = getBaseUrl(req);
      res.json({
        issuer: base,
        authorization_endpoint: `${base}/oauth/authorize`,
        token_endpoint: `${base}/oauth/token`,
        registration_endpoint: `${base}/oauth/register`,
        response_types_supported: ["code"],
        grant_types_supported: ["authorization_code"],
        token_endpoint_auth_methods_supported: ["client_secret_post"],
        code_challenge_methods_supported: ["S256"],
      });
    },
  );

  // Dynamic Client Registration
  router.post("/oauth/register", (req: Request, res: Response) => {
    const { redirect_uris, client_name } = req.body ?? {};

    if (
      !redirect_uris ||
      !Array.isArray(redirect_uris) ||
      redirect_uris.length === 0
    ) {
      res.status(400).json({ error: "redirect_uris is required" });
      return;
    }

    const clientId = `client_${crypto.randomUUID()}`;
    const clientSecret = `secret_${crypto.randomBytes(32).toString("hex")}`;

    const client: RegisteredClient = {
      clientId,
      clientSecret,
      redirectUris: redirect_uris,
      clientName: client_name,
      registeredAt: Date.now(),
    };
    clients.set(clientId, client);

    res.status(201).json({
      client_id: clientId,
      client_secret: clientSecret,
      client_name: client_name ?? null,
      redirect_uris,
      token_endpoint_auth_method: "client_secret_post",
      grant_types: ["authorization_code"],
      response_types: ["code"],
    });
  });

  // Authorization endpoint - redirects to login page
  router.get("/oauth/authorize", (req: Request, res: Response) => {
    cleanupExpiredRequests();

    const {
      client_id,
      redirect_uri,
      state,
      code_challenge,
      code_challenge_method,
      scope,
    } = req.query as Record<string, string>;

    if (!client_id || !redirect_uri) {
      res
        .status(400)
        .json({ error: "client_id and redirect_uri are required" });
      return;
    }

    const client = clients.get(client_id);
    if (!client) {
      res.status(400).json({ error: "Unknown client_id" });
      return;
    }

    if (!client.redirectUris.includes(redirect_uri)) {
      res.status(400).json({ error: "Invalid redirect_uri" });
      return;
    }

    if (code_challenge_method && code_challenge_method !== "S256") {
      res
        .status(400)
        .json({ error: "Only S256 code_challenge_method is supported" });
      return;
    }

    const requestId = crypto.randomBytes(32).toString("base64url");
    pendingRequests.set(requestId, {
      clientId: client_id,
      redirectUri: redirect_uri,
      state: state || "",
      codeChallenge: code_challenge || "",
      codeChallengeMethod: code_challenge_method || "S256",
      scopes: scope ? scope.split(" ") : [],
      createdAt: Date.now(),
      failedAttempts: 0,
    });

    const base = getBaseUrl(req);
    res.redirect(302, `${base}/oauth/login?request_id=${requestId}`);
  });

  // Login page - GET
  router.get("/oauth/login", (req: Request, res: Response) => {
    const requestId = req.query.request_id as string;
    const pending = requestId ? pendingRequests.get(requestId) : null;

    if (!pending) {
      htmlResponse(res, "Invalid or expired login request.", 400);
      return;
    }

    if (Date.now() - pending.createdAt > PENDING_REQUEST_TTL_MS) {
      pendingRequests.delete(requestId);
      htmlResponse(
        res,
        "Login request expired. Please restart the authorization flow.",
        400,
      );
      return;
    }

    htmlResponse(res, loginHtml(requestId));
  });

  // Login page - POST
  router.post("/oauth/login", (req: Request, res: Response) => {
    const requestId = String(req.body?.request_id ?? "");
    const password = String(req.body?.password ?? "");

    const pending = pendingRequests.get(requestId);
    if (!pending) {
      htmlResponse(res, "Invalid or expired login request.", 400);
      return;
    }

    if (Date.now() - pending.createdAt > PENDING_REQUEST_TTL_MS) {
      pendingRequests.delete(requestId);
      htmlResponse(
        res,
        "Login request expired. Please restart the authorization flow.",
        400,
      );
      return;
    }

    // Global rate limit
    const now = Date.now();
    if (now < globalLockoutUntil) {
      htmlResponse(
        res,
        "Too many failed login attempts. Please try again later.",
        429,
      );
      return;
    }

    let expectedPassword: string;
    try {
      expectedPassword = getPassword();
    } catch {
      htmlResponse(res, "Server misconfigured. Contact administrator.", 500);
      return;
    }

    if (!constantTimeCompare(password, expectedPassword)) {
      pending.failedAttempts += 1;
      if (pending.failedAttempts >= MAX_FAILED_ATTEMPTS) {
        pendingRequests.delete(requestId);
      }

      // Track global failures
      const cutoff = now - GLOBAL_RATE_LIMIT_WINDOW_MS;
      const recentFailures = globalFailedAttempts.filter((t) => t > cutoff);
      recentFailures.push(now);
      globalFailedAttempts.length = 0;
      globalFailedAttempts.push(...recentFailures);

      if (globalFailedAttempts.length >= GLOBAL_MAX_FAILED_ATTEMPTS) {
        globalLockoutUntil = now + GLOBAL_LOCKOUT_MS;
        htmlResponse(
          res,
          "Too many failed login attempts. Please try again later, then restart the authorization flow from your client.",
          429,
        );
        return;
      }

      if (pending.failedAttempts >= MAX_FAILED_ATTEMPTS) {
        htmlResponse(
          res,
          "Too many failed attempts. Please restart the authorization flow.",
          403,
        );
        return;
      }

      const remaining = MAX_FAILED_ATTEMPTS - pending.failedAttempts;
      htmlResponse(
        res,
        loginHtml(
          requestId,
          `Invalid password. ${remaining} attempt(s) remaining.`,
        ),
      );
      return;
    }

    // Password correct - create auth code and redirect
    pendingRequests.delete(requestId);
    cleanupExpiredAuthCodes();

    const client = clients.get(pending.clientId);
    if (!client) {
      htmlResponse(
        res,
        "Client registration not found. Please restart the authorization flow from your client.",
        400,
      );
      return;
    }

    const codeValue = `auth_code_${crypto.randomBytes(16).toString("hex")}`;
    const authCode: AuthCode = {
      code: codeValue,
      clientId: pending.clientId,
      redirectUri: pending.redirectUri,
      scopes: pending.scopes,
      codeChallenge: pending.codeChallenge,
      expiresAt: Date.now() + AUTH_CODE_TTL_MS,
    };
    authCodes.set(codeValue, authCode);

    const redirectUrl = new URL(pending.redirectUri);
    redirectUrl.searchParams.set("code", codeValue);
    if (pending.state) {
      redirectUrl.searchParams.set("state", pending.state);
    }

    res.redirect(302, redirectUrl.toString());
  });

  // Token endpoint
  router.post("/oauth/token", (req: Request, res: Response) => {
    const {
      grant_type,
      code,
      redirect_uri,
      client_id,
      client_secret,
      code_verifier,
    } = req.body ?? {};

    if (grant_type !== "authorization_code") {
      res.status(400).json({ error: "unsupported_grant_type" });
      return;
    }

    if (!code || !client_id) {
      res.status(400).json({ error: "invalid_request" });
      return;
    }

    const client = clients.get(client_id);
    if (!client) {
      res.status(400).json({ error: "invalid_client" });
      return;
    }

    if (
      client_secret &&
      !constantTimeCompare(client_secret, client.clientSecret)
    ) {
      res.status(400).json({ error: "invalid_client" });
      return;
    }

    const authCode = authCodes.get(code);
    if (!authCode) {
      res.status(400).json({ error: "invalid_grant" });
      return;
    }

    if (Date.now() > authCode.expiresAt) {
      authCodes.delete(code);
      res.status(400).json({ error: "invalid_grant" });
      return;
    }

    if (authCode.clientId !== client_id) {
      res.status(400).json({ error: "invalid_grant" });
      return;
    }

    if (redirect_uri && authCode.redirectUri !== redirect_uri) {
      res.status(400).json({ error: "invalid_grant" });
      return;
    }

    // Verify PKCE
    if (authCode.codeChallenge) {
      if (!code_verifier) {
        res.status(400).json({ error: "invalid_grant" });
        return;
      }
      if (!verifyCodeChallenge(code_verifier, authCode.codeChallenge)) {
        res.status(400).json({ error: "invalid_grant" });
        return;
      }
    }

    // Consume the auth code
    authCodes.delete(code);

    const tokenValue = crypto.randomBytes(32).toString("hex");
    const token: AccessToken = {
      token: tokenValue,
      clientId: client_id,
      scopes: authCode.scopes,
      createdAt: Date.now(),
    };
    accessTokens.set(tokenValue, token);

    res.json({
      access_token: tokenValue,
      token_type: "Bearer",
      scope: authCode.scopes.join(" "),
    });
  });

  return router;
}

/**
 * Validate a Bearer token from the Authorization header.
 * Returns the token string if valid, or null if invalid.
 */
export function validateBearerToken(authHeader: string | undefined): boolean {
  if (!authHeader?.startsWith("Bearer ")) return false;
  const token = authHeader.slice("Bearer ".length).trim();
  return accessTokens.has(token);
}
