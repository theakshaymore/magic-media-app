import { Hono } from "hono";
import { zValidator } from "@hono/zod-validator";
import { setCookie } from "hono/cookie";
import {
  getOAuthRedirectUrl,
  exchangeCodeForSessionToken,
  deleteSession,
  MOCHA_SESSION_TOKEN_COOKIE_NAME,
  authMiddleware,
} from "@getmocha/users-service/backend";

type Env = {
  MOCHA_USERS_SERVICE_API_URL?: string;
  MOCHA_USERS_SERVICE_API_KEY?: string;
  OPENAI_API_KEY?: string;
  DB: D1Database;
};

// Minimal D1 type to satisfy TypeScript when Cloudflare types aren't available locally
type D1Database = {
  prepare: (...args: any[]) => {
    bind: (...args: any[]) => {
      first: () => Promise<any>;
      all: () => Promise<any>;
      run: () => Promise<any>;
    };
    first: () => Promise<any>;
    all: () => Promise<any>;
    run: () => Promise<any>;
  };
};
import { getCookie } from "hono/cookie";
import {
  CreateSequenceSchema,
  CreateEmailBlockSchema,
  UpdateEmailBlockSchema,
  CreateConnectionSchema,
  CreateTemplateSchema,
  ExportSequenceSchema,
  GenerateContentSchema,
} from "@/shared/types";
import OpenAI from "openai";
import { v4 as uuidv4 } from "uuid";

const app = new Hono<{ Bindings: Env }>();

const DEV_SESSION_TOKEN = "dev-session-token";
const isPlaceholderValue = (value?: string) => {
  if (!value) return true;
  const normalized = value.trim().toLowerCase();
  if (!normalized) return true;
  return (
    normalized === "mock" ||
    normalized === "test" ||
    normalized === "placeholder" ||
    normalized.startsWith("mock-") ||
    normalized.startsWith("test-") ||
    normalized.includes("mock-users-service")
  );
};

const isMochaAuthConfigured = (env: Env) => {
  const apiUrl = env?.MOCHA_USERS_SERVICE_API_URL;
  const apiKey = env?.MOCHA_USERS_SERVICE_API_KEY;

  if (isPlaceholderValue(apiUrl) || isPlaceholderValue(apiKey)) {
    return false;
  }

  return Boolean(apiUrl && apiKey);
};

const devUser = {
  id: "Akshay",
  email: "akshay@gmail.com",
  name: "Local Dev User",
};

const mochaAuthMiddleware = async (c: any, next: any) => {
  // Check for manual session first
  const sessionToken = getCookie(c, "session_token");
  if (sessionToken) {
    const db = c.env.DB;
    const session = await db
      .prepare("SELECT us.*, u.* FROM user_sessions us JOIN users u ON us.user_id = u.id WHERE us.token = ? AND us.expires_at > datetime('now')")
      .bind(sessionToken)
      .first();

    if (session) {
      c.set("user", {
        id: session.user_id,
        email: session.email,
        name: session.name,
      });
      return next();
    }
  }

  // Fall back to Mocha OAuth
  if (!isMochaAuthConfigured(c.env)) {
    c.set("user", devUser);
    return next();
  }

  return authMiddleware(c, next);
};

const ADMIN_SESSION_COOKIE_NAME = "admin_session_token";

// Admin authentication middleware
const adminAuthMiddleware = async (c: any, next: any) => {
  const sessionToken = getCookie(c, ADMIN_SESSION_COOKIE_NAME);

  if (!sessionToken) {
    return c.json({ error: "Unauthorized" }, 401);
  }

  const db = c.env.DB;
  const session = await db
    .prepare(
      "SELECT * FROM admin_sessions WHERE token = ? AND expires_at > datetime('now')"
    )
    .bind(sessionToken)
    .first();

  if (!session) {
    return c.json({ error: "Unauthorized" }, 401);
  }

  await next();
};

// ===== ADMIN ROUTES =====

// Admin login
app.post("/api/admin/login", async (c) => {
  const db = c.env.DB;
  const body = await c.req.json();

  const { email, password } = body;

  // Check credentials (hardcoded for now)
  if (email === "gotayjust@hotmail.com" && password === "inderpalastra11") {
    // Create session
    const sessionId = uuidv4();
    const token = uuidv4();
    const now = new Date();
    const expiresAt = new Date(now.getTime() + 24 * 60 * 60 * 1000); // 24 hours

    await db
      .prepare(
        `
      INSERT INTO admin_sessions (id, admin_email, token, created_at, expires_at)
      VALUES (?, ?, ?, ?, ?)
    `
      )
      .bind(sessionId, email, token, now.toISOString(), expiresAt.toISOString())
      .run();

    setCookie(c, ADMIN_SESSION_COOKIE_NAME, token, {
      httpOnly: true,
      path: "/",
      sameSite: "none",
      secure: true,
      maxAge: 24 * 60 * 60, // 24 hours
    });

    return c.json({ success: true }, 200);
  }

  return c.json({ error: "Invalid credentials" }, 401);
});

// Admin logout
app.post("/api/admin/logout", async (c) => {
  const db = c.env.DB;
  const sessionToken = getCookie(c, ADMIN_SESSION_COOKIE_NAME);

  if (sessionToken) {
    await db
      .prepare("DELETE FROM admin_sessions WHERE token = ?")
      .bind(sessionToken)
      .run();
  }

  setCookie(c, ADMIN_SESSION_COOKIE_NAME, "", {
    httpOnly: true,
    path: "/",
    sameSite: "none",
    secure: true,
    maxAge: 0,
  });

  return c.json({ success: true }, 200);
});

// Get all users (admin only)
app.get("/api/admin/users", adminAuthMiddleware, async (c) => {
  const db = c.env.DB;

  // Fetch all user credits records
  const creditsRecords = await db.prepare("SELECT * FROM user_credits").all();

  // Get user details and credits
  const users = [];
  for (const creditsRecord of creditsRecords.results as any[]) {
    const userId = creditsRecord.user_id;

    // Get the first sequence to determine when user joined
    const userSequence = await db
      .prepare(
        "SELECT user_id, created_at FROM sequences WHERE user_id = ? ORDER BY created_at ASC LIMIT 1"
      )
      .bind(userId)
      .first();

    // Use sequence creation date or credit record date
    const createdAt =
      userSequence?.created_at ||
      creditsRecord.last_updated ||
      new Date().toISOString();

    users.push({
      id: userId,
      email: creditsRecord.email || userId, // Use stored email from user_credits
      created_at: createdAt,
      user_id: userId,
      credits_balance: creditsRecord.credits_balance || 0,
      total_credits_used: creditsRecord.total_credits_used || 0,
      plan: creditsRecord.plan || "Basic",
      is_active: creditsRecord.is_active !== false,
    });
  }

  return c.json(users);
});

// Update user (admin only)
app.put("/api/admin/users/:userId", adminAuthMiddleware, async (c) => {
  const db = c.env.DB;
  const userId = c.req.param("userId");
  const body = await c.req.json();
  const now = new Date().toISOString();

  // Update user credits and plan
  await db
    .prepare(
      `
    UPDATE user_credits 
    SET credits_balance = ?, plan = ?, last_updated = ?
    WHERE user_id = ?
  `
    )
    .bind(body.credits_balance, body.plan, now, userId)
    .run();

  // Note: Email changes would require integration with Mocha's user service
  // For now, we'll skip email updates

  return c.json({ success: true });
});

// Toggle user active status (admin only)
app.post(
  "/api/admin/users/:userId/toggle-active",
  adminAuthMiddleware,
  async (c) => {
    const db = c.env.DB;
    const userId = c.req.param("userId");
    const now = new Date().toISOString();

    // Get current status
    const credits = await db
      .prepare("SELECT is_active FROM user_credits WHERE user_id = ?")
      .bind(userId)
      .first();

    const newStatus = !(credits?.is_active !== false);

    await db
      .prepare(
        `
    UPDATE user_credits 
    SET is_active = ?, last_updated = ?
    WHERE user_id = ?
  `
      )
      .bind(newStatus, now, userId)
      .run();

    return c.json({ success: true });
  }
);

// ===== AUTH ROUTES =====

// Manual Registration
app.post("/api/auth/register", async (c) => {
  const db = c.env.DB;
  const body = await c.req.json();
  const { email, password, name } = body;

  // Validate input
  if (!email || !password) {
    return c.json({ error: "Email and password are required" }, 400);
  }

  if (password.length < 6) {
    return c.json({ error: "Password must be at least 6 characters" }, 400);
  }

  try {
    // Check if user already exists
    const existingUser = await db
      .prepare("SELECT * FROM users WHERE email = ?")
      .bind(email.toLowerCase())
      .first();

    if (existingUser) {
      return c.json({ error: "Email already registered" }, 409);
    }

    // Create password hash (simple hash for demo - in production use bcrypt)
    const passwordHash = await hashPassword(password);
    const userId = uuidv4();
    const now = new Date().toISOString();

    // Create user
    await db
      .prepare(
        "INSERT INTO users (id, email, password_hash, name, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)"
      )
      .bind(userId, email.toLowerCase(), passwordHash, name || "", now, now)
      .run();

    // Initialize user credits
    await db
      .prepare(
        "INSERT INTO user_credits (user_id, credits_balance, total_credits_used, last_updated, email) VALUES (?, 10000, 0, ?, ?)"
      )
      .bind(userId, now, email.toLowerCase())
      .run();

    // Create session
    const sessionId = uuidv4();
    const sessionToken = uuidv4();
    const expiresAt = new Date(Date.now() + 60 * 24 * 60 * 60 * 1000); // 60 days

    await db
      .prepare(
        "INSERT INTO user_sessions (id, user_id, token, created_at, expires_at) VALUES (?, ?, ?, ?, ?)"
      )
      .bind(sessionId, userId, sessionToken, now, expiresAt.toISOString())
      .run();

    setCookie(c, "session_token", sessionToken, {
      httpOnly: true,
      path: "/",
      sameSite: "none",
      secure: true,
      maxAge: 60 * 24 * 60 * 60, // 60 days
    });

    return c.json({
      success: true,
      user: { id: userId, email: email.toLowerCase(), name: name || "" },
    });
  } catch (error) {
    console.error("Registration error:", error);
    return c.json({ error: "Registration failed" }, 500);
  }
});

// Manual Login
app.post("/api/auth/login", async (c) => {
  const db = c.env.DB;
  const body = await c.req.json();
  const { email, password } = body;

  if (!email || !password) {
    return c.json({ error: "Email and password are required" }, 400);
  }

  try {
    // Find user
    const user = await db
      .prepare("SELECT * FROM users WHERE email = ?")
      .bind(email.toLowerCase())
      .first();

    if (!user) {
      return c.json({ error: "Invalid email or password" }, 401);
    }

    // Verify password
    const passwordValid = await verifyPassword(password, user.password_hash as string);
    if (!passwordValid) {
      return c.json({ error: "Invalid email or password" }, 401);
    }

    // Create session
    const sessionId = uuidv4();
    const sessionToken = uuidv4();
    const now = new Date().toISOString();
    const expiresAt = new Date(Date.now() + 60 * 24 * 60 * 60 * 1000); // 60 days

    await db
      .prepare(
        "INSERT INTO user_sessions (id, user_id, token, created_at, expires_at) VALUES (?, ?, ?, ?, ?)"
      )
      .bind(sessionId, user.id, sessionToken, now, expiresAt.toISOString())
      .run();

    setCookie(c, "session_token", sessionToken, {
      httpOnly: true,
      path: "/",
      sameSite: "none",
      secure: true,
      maxAge: 60 * 24 * 60 * 60, // 60 days
    });

    return c.json({
      success: true,
      user: { id: user.id, email: user.email, name: user.name },
    });
  } catch (error) {
    console.error("Login error:", error);
    return c.json({ error: "Login failed" }, 500);
  }
});

// Password hashing helper (simple implementation - use bcrypt in production)
async function hashPassword(password: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(password);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

async function verifyPassword(password: string, hash: string): Promise<boolean> {
  const passwordHash = await hashPassword(password);
  return passwordHash === hash;
}

// Get OAuth redirect URL
app.get("/api/oauth/google/redirect_url", async (c) => {
  if (!isMochaAuthConfigured(c.env)) {
    return c.json(
      { redirectUrl: "https://accounts.google.com/o/oauth2/auth?mock=1" },
      200
    );
  }

  const redirectUrl = await getOAuthRedirectUrl("google", {
    apiUrl: c.env.MOCHA_USERS_SERVICE_API_URL!,
    apiKey: c.env.MOCHA_USERS_SERVICE_API_KEY!,
  });

  return c.json({ redirectUrl }, 200);
});

// Exchange code for session token
app.post("/api/sessions", async (c) => {
  const body = await c.req.json();

  if (!body.code) {
    return c.json({ error: "No authorization code provided" }, 400);
  }

  const sessionToken = isMochaAuthConfigured(c.env)
    ? await exchangeCodeForSessionToken(body.code, {
        apiUrl: c.env.MOCHA_USERS_SERVICE_API_URL!,
        apiKey: c.env.MOCHA_USERS_SERVICE_API_KEY!,
      })
    : DEV_SESSION_TOKEN;

  setCookie(c, MOCHA_SESSION_TOKEN_COOKIE_NAME, sessionToken, {
    httpOnly: true,
    path: "/",
    sameSite: "none",
    secure: true,
    maxAge: 60 * 24 * 60 * 60, // 60 days
  });

  return c.json({ success: true }, 200);
});

// Get current user
app.get("/api/users/me", mochaAuthMiddleware, async (c) => {
  return c.json(c.get("user"));
});

// Get user credits
app.get("/api/users/me/credits", mochaAuthMiddleware, async (c) => {
  const db = c.env.DB;
  const user = c.get("user");

  if (!user) {
    return c.json({ error: "Unauthorized" }, 401);
  }

  // Get or create user credits record
  let userCredits = await db
    .prepare("SELECT * FROM user_credits WHERE user_id = ?")
    .bind(user.id)
    .first();

  const now = new Date().toISOString();

  if (!userCredits) {
    // Initialize credits for new user
    await db
      .prepare(
        `
      INSERT INTO user_credits (user_id, credits_balance, total_credits_used, last_updated, email)
      VALUES (?, 10000, 0, ?, ?)
    `
      )
      .bind(user.id, now, user.email)
      .run();

    userCredits = await db
      .prepare("SELECT * FROM user_credits WHERE user_id = ?")
      .bind(user.id)
      .first();
  } else {
    // Update email if it's missing or different (sync with auth service)
    if (!userCredits.email || userCredits.email !== user.email) {
      await db
        .prepare(
          `
        UPDATE user_credits 
        SET email = ?, last_updated = ?
        WHERE user_id = ?
      `
        )
        .bind(user.email, now, user.id)
        .run();

      userCredits = await db
        .prepare("SELECT * FROM user_credits WHERE user_id = ?")
        .bind(user.id)
        .first();
    }
  }

  return c.json(userCredits);
});

// Logout
app.get("/api/logout", async (c) => {
  const db = c.env.DB;

  // Clear manual session
  const manualSessionToken = getCookie(c, "session_token");
  if (manualSessionToken) {
    await db
      .prepare("DELETE FROM user_sessions WHERE token = ?")
      .bind(manualSessionToken)
      .run();

    setCookie(c, "session_token", "", {
      httpOnly: true,
      path: "/",
      sameSite: "none",
      secure: true,
      maxAge: 0,
    });
  }

  // Clear OAuth session
  const sessionToken = getCookie(c, MOCHA_SESSION_TOKEN_COOKIE_NAME);

  if (typeof sessionToken === "string" && isMochaAuthConfigured(c.env)) {
    await deleteSession(sessionToken, {
      apiUrl: c.env.MOCHA_USERS_SERVICE_API_URL!,
      apiKey: c.env.MOCHA_USERS_SERVICE_API_KEY!,
    });
  }

  setCookie(c, MOCHA_SESSION_TOKEN_COOKIE_NAME, "", {
    httpOnly: true,
    path: "/",
    sameSite: "none",
    secure: true,
    maxAge: 0,
  });

  return c.json({ success: true }, 200);
});

// ===== SEQUENCE ROUTES =====

// Get all sequences for authenticated user
app.get("/api/sequences", mochaAuthMiddleware, async (c) => {
  const db = c.env.DB;
  const user = c.get("user");

  if (!user) {
    return c.json({ error: "Unauthorized" }, 401);
  }

  const sequences = await db
    .prepare(
      "SELECT * FROM sequences WHERE user_id = ? ORDER BY created_at DESC"
    )
    .bind(user.id)
    .all();

  return c.json(sequences.results);
});

// Create sequence
app.post(
  "/api/sequences",
  mochaAuthMiddleware,
  zValidator("json", CreateSequenceSchema),
  async (c) => {
    const db = c.env.DB;
    const user = c.get("user");
    const body = c.req.valid("json");
    const id = uuidv4();
    const now = new Date().toISOString();

    if (!user) {
      return c.json({ error: "Unauthorized" }, 401);
    }

    await db
      .prepare(
        `
    INSERT INTO sequences (id, name, description, user_id, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `
      )
      .bind(id, body.name, body.description || "", user.id, now, now)
      .run();

    const sequence = await db
      .prepare("SELECT * FROM sequences WHERE id = ?")
      .bind(id)
      .first();
    return c.json(sequence);
  }
);

// Update sequence
app.put("/api/sequences/:id", mochaAuthMiddleware, async (c) => {
  const db = c.env.DB;
  const user = c.get("user");
  const sequenceId = c.req.param("id");
  const body = await c.req.json();
  const now = new Date().toISOString();

  if (!user) {
    return c.json({ error: "Unauthorized" }, 401);
  }

  // Verify ownership
  const sequence = await db
    .prepare("SELECT * FROM sequences WHERE id = ? AND user_id = ?")
    .bind(sequenceId, user.id)
    .first();

  if (!sequence) {
    return c.json({ error: "Sequence not found" }, 404);
  }

  // Validate input
  if (!body.name || !body.name.trim()) {
    return c.json({ error: "Name is required" }, 400);
  }

  // Update sequence
  await db
    .prepare(
      `
    UPDATE sequences SET name = ?, description = ?, updated_at = ? WHERE id = ?
  `
    )
    .bind(body.name.trim(), body.description || "", now, sequenceId)
    .run();

  const updatedSequence = await db
    .prepare("SELECT * FROM sequences WHERE id = ?")
    .bind(sequenceId)
    .first();
  return c.json(updatedSequence);
});

// Get sequence with blocks and connections
app.get("/api/sequences/:id", mochaAuthMiddleware, async (c) => {
  const db = c.env.DB;
  const user = c.get("user");
  const sequenceId = c.req.param("id");

  if (!user) {
    return c.json({ error: "Unauthorized" }, 401);
  }

  const sequence = await db
    .prepare("SELECT * FROM sequences WHERE id = ? AND user_id = ?")
    .bind(sequenceId, user.id)
    .first();

  if (!sequence) {
    return c.json({ error: "Sequence not found" }, 404);
  }

  const blocks = await db
    .prepare("SELECT * FROM email_blocks WHERE sequence_id = ?")
    .bind(sequenceId)
    .all();
  const connections = await db
    .prepare("SELECT * FROM sequence_connections WHERE sequence_id = ?")
    .bind(sequenceId)
    .all();

  return c.json({
    sequence,
    blocks: blocks.results,
    connections: connections.results,
  });
});

// Delete sequence
app.delete("/api/sequences/:id", mochaAuthMiddleware, async (c) => {
  const db = c.env.DB;
  const user = c.get("user");
  const sequenceId = c.req.param("id");

  if (!user) {
    return c.json({ error: "Unauthorized" }, 401);
  }

  // Verify ownership
  const sequence = await db
    .prepare("SELECT * FROM sequences WHERE id = ? AND user_id = ?")
    .bind(sequenceId, user.id)
    .first();

  if (!sequence) {
    return c.json({ error: "Sequence not found" }, 404);
  }

  // Delete in order: connections, blocks, sequence
  await db
    .prepare("DELETE FROM sequence_connections WHERE sequence_id = ?")
    .bind(sequenceId)
    .run();
  await db
    .prepare("DELETE FROM email_blocks WHERE sequence_id = ?")
    .bind(sequenceId)
    .run();
  await db.prepare("DELETE FROM sequences WHERE id = ?").bind(sequenceId).run();

  return c.json({ success: true });
});

// Duplicate sequence
app.post("/api/sequences/:id/duplicate", mochaAuthMiddleware, async (c) => {
  const db = c.env.DB;
  const user = c.get("user");
  const sequenceId = c.req.param("id");
  const newSequenceId = uuidv4();
  const now = new Date().toISOString();

  if (!user) {
    return c.json({ error: "Unauthorized" }, 401);
  }

  // Get original sequence
  const originalSequence = await db
    .prepare("SELECT * FROM sequences WHERE id = ? AND user_id = ?")
    .bind(sequenceId, user.id)
    .first();

  if (!originalSequence) {
    return c.json({ error: "Sequence not found" }, 404);
  }

  // Duplicate sequence
  await db
    .prepare(
      `
    INSERT INTO sequences (id, name, description, user_id, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `
    )
    .bind(
      newSequenceId,
      `${String(originalSequence.name)} (Copy)`,
      originalSequence.description,
      user.id,
      now,
      now
    )
    .run();

  // Get original blocks
  const originalBlocks = await db
    .prepare("SELECT * FROM email_blocks WHERE sequence_id = ?")
    .bind(sequenceId)
    .all();
  const blockIdMap = new Map<string, string>();

  // Duplicate blocks
  for (const block of originalBlocks.results as any[]) {
    const newBlockId = uuidv4();
    blockIdMap.set(block.id, newBlockId);

    await db
      .prepare(
        `
      INSERT INTO email_blocks (id, sequence_id, type, name, subject_line, preview_text, body_copy, cta_text, cta_url, send_delay_hours, position_x, position_y, notes, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `
      )
      .bind(
        newBlockId,
        newSequenceId,
        block.type,
        block.name,
        block.subject_line,
        block.preview_text,
        block.body_copy,
        block.cta_text,
        block.cta_url,
        block.send_delay_hours,
        block.position_x,
        block.position_y,
        block.notes,
        now,
        now
      )
      .run();
  }

  // Duplicate connections
  const originalConnections = await db
    .prepare("SELECT * FROM sequence_connections WHERE sequence_id = ?")
    .bind(sequenceId)
    .all();

  for (const connection of originalConnections.results as any[]) {
    const newConnectionId = uuidv4();
    const newSourceId = blockIdMap.get(connection.source_block_id);
    const newTargetId = blockIdMap.get(connection.target_block_id);

    if (newSourceId && newTargetId) {
      await db
        .prepare(
          `
        INSERT INTO sequence_connections (id, sequence_id, source_block_id, target_block_id, condition_type, custom_label, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `
        )
        .bind(
          newConnectionId,
          newSequenceId,
          newSourceId,
          newTargetId,
          connection.condition_type,
          connection.custom_label || null,
          now,
          now
        )
        .run();
    }
  }

  const newSequence = await db
    .prepare("SELECT * FROM sequences WHERE id = ?")
    .bind(newSequenceId)
    .first();
  return c.json(newSequence);
});

// ===== EMAIL BLOCK ROUTES =====

// Create email block
app.post(
  "/api/sequences/:id/blocks",
  mochaAuthMiddleware,
  zValidator("json", CreateEmailBlockSchema),
  async (c) => {
    const db = c.env.DB;
    const user = c.get("user");
    const sequenceId = c.req.param("id");
    const body = c.req.valid("json");
    const blockId = uuidv4();
    const now = new Date().toISOString();

    if (!user) {
      return c.json({ error: "Unauthorized" }, 401);
    }

    // Verify sequence ownership
    const sequence = await db
      .prepare("SELECT * FROM sequences WHERE id = ? AND user_id = ?")
      .bind(sequenceId, user.id)
      .first();

    if (!sequence) {
      return c.json({ error: "Sequence not found" }, 404);
    }

    await db
      .prepare(
        `
    INSERT INTO email_blocks (id, sequence_id, type, name, position_x, position_y, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `
      )
      .bind(
        blockId,
        sequenceId,
        body.type,
        body.name,
        body.position_x,
        body.position_y,
        now,
        now
      )
      .run();

    const block = await db
      .prepare("SELECT * FROM email_blocks WHERE id = ?")
      .bind(blockId)
      .first();
    return c.json(block);
  }
);

// Update email block
app.put(
  "/api/blocks/:id",
  mochaAuthMiddleware,
  zValidator("json", UpdateEmailBlockSchema),
  async (c) => {
    const db = c.env.DB;
    const user = c.get("user");
    const blockId = c.req.param("id");
    const body = c.req.valid("json");
    const now = new Date().toISOString();

    if (!user) {
      return c.json({ error: "Unauthorized" }, 401);
    }

    // Verify block ownership through sequence
    const block = await db
      .prepare(
        `
    SELECT eb.* FROM email_blocks eb
    JOIN sequences s ON eb.sequence_id = s.id
    WHERE eb.id = ? AND s.user_id = ?
  `
      )
      .bind(blockId, user.id)
      .first();

    if (!block) {
      return c.json({ error: "Block not found" }, 404);
    }

    const updates = Object.entries(body).filter(
      ([_, value]) => value !== undefined
    );
    if (updates.length === 0) {
      return c.json({ error: "No fields to update" }, 400);
    }

    const setClause = updates.map(([key, _]) => `${key} = ?`).join(", ");
    const values = [...updates.map(([_, value]) => value), now, blockId];

    await db
      .prepare(
        `
    UPDATE email_blocks SET ${setClause}, updated_at = ? WHERE id = ?
  `
      )
      .bind(...values)
      .run();

    const updatedBlock = await db
      .prepare("SELECT * FROM email_blocks WHERE id = ?")
      .bind(blockId)
      .first();
    return c.json(updatedBlock);
  }
);

// Duplicate block
app.post("/api/blocks/:id/duplicate", mochaAuthMiddleware, async (c) => {
  const db = c.env.DB;
  const user = c.get("user");
  const blockId = c.req.param("id");
  const newBlockId = uuidv4();
  const now = new Date().toISOString();

  if (!user) {
    return c.json({ error: "Unauthorized" }, 401);
  }

  // Fetch the source block from database to get latest content
  const sourceBlock = await db
    .prepare(
      `
    SELECT eb.* FROM email_blocks eb
    JOIN sequences s ON eb.sequence_id = s.id
    WHERE eb.id = ? AND s.user_id = ?
  `
    )
    .bind(blockId, user.id)
    .first();

  if (!sourceBlock) {
    return c.json({ error: "Block not found" }, 404);
  }

  // Calculate new position offset from original
  const newPositionX = (sourceBlock.position_x as number) + 350;
  const newPositionY = (sourceBlock.position_y as number) + 50;

  // Create new block with all content from source block
  await db
    .prepare(
      `
    INSERT INTO email_blocks (
      id, sequence_id, type, name, subject_line, preview_text, 
      body_copy, cta_text, cta_url, send_delay_hours, 
      position_x, position_y, notes, created_at, updated_at
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `
    )
    .bind(
      newBlockId,
      sourceBlock.sequence_id,
      sourceBlock.type,
      `${sourceBlock.name} (Copy)`,
      sourceBlock.subject_line || null,
      sourceBlock.preview_text || null,
      sourceBlock.body_copy || null,
      sourceBlock.cta_text || null,
      sourceBlock.cta_url || null,
      sourceBlock.send_delay_hours || 0,
      newPositionX,
      newPositionY,
      sourceBlock.notes || null,
      now,
      now
    )
    .run();

  // Return the newly created block
  const newBlock = await db
    .prepare("SELECT * FROM email_blocks WHERE id = ?")
    .bind(newBlockId)
    .first();
  return c.json(newBlock);
});

// Delete block
app.delete("/api/blocks/:id", mochaAuthMiddleware, async (c) => {
  const db = c.env.DB;
  const user = c.get("user");
  const blockId = c.req.param("id");

  if (!user) {
    return c.json({ error: "Unauthorized" }, 401);
  }

  // Verify block ownership through sequence
  const block = await db
    .prepare(
      `
    SELECT eb.* FROM email_blocks eb
    JOIN sequences s ON eb.sequence_id = s.id
    WHERE eb.id = ? AND s.user_id = ?
  `
    )
    .bind(blockId, user.id)
    .first();

  if (!block) {
    return c.json({ error: "Block not found" }, 404);
  }

  // Delete connections first
  await db
    .prepare(
      "DELETE FROM sequence_connections WHERE source_block_id = ? OR target_block_id = ?"
    )
    .bind(blockId, blockId)
    .run();

  // Delete block
  await db.prepare("DELETE FROM email_blocks WHERE id = ?").bind(blockId).run();

  return c.json({ success: true });
});

// ===== CONNECTION ROUTES =====

// Create connection
app.post(
  "/api/connections",
  mochaAuthMiddleware,
  zValidator("json", CreateConnectionSchema),
  async (c) => {
    const db = c.env.DB;
    const user = c.get("user");
    const body = c.req.valid("json");
    const connectionId = uuidv4();
    const now = new Date().toISOString();

    if (!user) {
      return c.json({ error: "Unauthorized" }, 401);
    }

    // Verify sequence ownership
    const sequence = await db
      .prepare("SELECT * FROM sequences WHERE id = ? AND user_id = ?")
      .bind(body.sequence_id, user.id)
      .first();

    if (!sequence) {
      return c.json({ error: "Sequence not found" }, 404);
    }

    await db
      .prepare(
        `
    INSERT INTO sequence_connections (id, sequence_id, source_block_id, target_block_id, condition_type, custom_label, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `
      )
      .bind(
        connectionId,
        body.sequence_id,
        body.source_block_id,
        body.target_block_id,
        body.condition_type,
        body.custom_label || null,
        now,
        now
      )
      .run();

    const connection = await db
      .prepare("SELECT * FROM sequence_connections WHERE id = ?")
      .bind(connectionId)
      .first();
    return c.json(connection);
  }
);

// Delete connection
app.delete("/api/connections/:id", mochaAuthMiddleware, async (c) => {
  const db = c.env.DB;
  const user = c.get("user");
  const connectionId = c.req.param("id");

  if (!user) {
    return c.json({ error: "Unauthorized" }, 401);
  }

  // Verify connection ownership through sequence
  const connection = await db
    .prepare(
      `
    SELECT sc.* FROM sequence_connections sc
    JOIN sequences s ON sc.sequence_id = s.id
    WHERE sc.id = ? AND s.user_id = ?
  `
    )
    .bind(connectionId, user.id)
    .first();

  if (!connection) {
    return c.json({ error: "Connection not found" }, 404);
  }

  await db
    .prepare("DELETE FROM sequence_connections WHERE id = ?")
    .bind(connectionId)
    .run();
  return c.json({ success: true });
});

// ===== TEMPLATE ROUTES =====

// Get public templates
app.get("/api/templates", async (c) => {
  const db = c.env.DB;
  const templates = await db
    .prepare(
      "SELECT * FROM sequence_templates WHERE is_public = TRUE ORDER BY created_at DESC"
    )
    .all();

  return c.json(templates.results);
});

// Get user's saved templates
app.get("/api/user-templates", mochaAuthMiddleware, async (c) => {
  const db = c.env.DB;
  const user = c.get("user");

  if (!user) {
    return c.json({ error: "Unauthorized" }, 401);
  }

  const templates = await db
    .prepare(
      "SELECT * FROM user_templates WHERE user_id = ? ORDER BY created_at DESC"
    )
    .bind(user.id)
    .all();

  return c.json(templates.results);
});

// Delete user template
app.delete("/api/user-templates/:id", mochaAuthMiddleware, async (c) => {
  const db = c.env.DB;
  const user = c.get("user");
  const templateId = c.req.param("id");

  if (!user) {
    return c.json({ error: "Unauthorized" }, 401);
  }

  // Verify ownership
  const template = await db
    .prepare("SELECT * FROM user_templates WHERE id = ? AND user_id = ?")
    .bind(templateId, user.id)
    .first();

  if (!template) {
    return c.json({ error: "Template not found" }, 404);
  }

  await db
    .prepare("DELETE FROM user_templates WHERE id = ?")
    .bind(templateId)
    .run();

  return c.json({ success: true });
});

// Save sequence as template
app.post(
  "/api/sequences/:id/save-template",
  mochaAuthMiddleware,
  zValidator("json", CreateTemplateSchema),
  async (c) => {
    const db = c.env.DB;
    const user = c.get("user");
    const sequenceId = c.req.param("id");
    const body = c.req.valid("json");
    const templateId = uuidv4();
    const now = new Date().toISOString();

    if (!user) {
      return c.json({ error: "Unauthorized" }, 401);
    }

    // Get sequence data
    const sequence = await db
      .prepare("SELECT * FROM sequences WHERE id = ? AND user_id = ?")
      .bind(sequenceId, user.id)
      .first();

    if (!sequence) {
      return c.json({ error: "Sequence not found" }, 404);
    }

    const blocks = await db
      .prepare("SELECT * FROM email_blocks WHERE sequence_id = ?")
      .bind(sequenceId)
      .all();
    const connections = await db
      .prepare("SELECT * FROM sequence_connections WHERE sequence_id = ?")
      .bind(sequenceId)
      .all();

    const sequenceData = JSON.stringify({
      sequence,
      blocks: blocks.results,
      connections: connections.results,
    });

    // Save to user_templates instead of sequence_templates for user's personal templates
    await db
      .prepare(
        `
    INSERT INTO user_templates (id, name, description, user_id, sequence_data, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `
      )
      .bind(
        templateId,
        body.name,
        body.description || "",
        user.id,
        sequenceData,
        now,
        now
      )
      .run();

    const template = await db
      .prepare("SELECT * FROM user_templates WHERE id = ?")
      .bind(templateId)
      .first();
    return c.json(template);
  }
);

// ===== AI CONTENT GENERATION =====

// Helper function to generate sample content programmatically
function generateSampleContent(type: string, tone: string, answers: Record<string, string>, customSubject?: string, customCTA?: string) {
  const blockConfig: Record<string, any> = {
    welcome: {
      name: "Welcome Email",
      defaultSubject: "Welcome to Our Community! 🎉",
      defaultBody: `Hello and welcome!\n\nWe're thrilled to have you join our community. As a new member, you're now part of something special.\n\nHere's what you can expect from us:\n• Exclusive updates and insights\n• Special member-only offers\n• Expert tips and resources\n\nWe're committed to providing you with valuable content that helps you achieve your goals.\n\nLet's get started on this exciting journey together!`,
      defaultCTA: "Get Started",
    },
    "follow-up": {
      name: "Follow-Up Email",
      defaultSubject: "Just Checking In...",
      defaultBody: `Hi there!\n\nI wanted to follow up with you and see how things are going. Your success is important to us, and we're here to help.\n\nHave you had a chance to explore everything we have to offer? If you have any questions or need assistance, don't hesitate to reach out.\n\nWe've prepared some resources that might be helpful for you.\n\nLooking forward to hearing from you!`,
      defaultCTA: "View Resources",
    },
    offer: {
      name: "Special Offer Email",
      defaultSubject: "🎁 Exclusive Offer Just For You!",
      defaultBody: `Great news!\n\nWe have an exclusive offer that we think you'll love. For a limited time, you can take advantage of this special promotion.\n\nThis is our way of saying thank you for being part of our community. We want to help you get the most value possible.\n\nDon't miss out on this opportunity - this offer won't last forever!\n\nClaim your special discount today and start enjoying the benefits.`,
      defaultCTA: "Claim Offer Now",
    },
    reminder: {
      name: "Friendly Reminder",
      defaultSubject: "⏰ Don't Forget - Action Required",
      defaultBody: `Quick reminder!\n\nWe noticed you haven't completed your setup yet. We want to make sure you don't miss out on all the great features available to you.\n\nIt only takes a few minutes to get everything configured, and you'll be glad you did.\n\nTake a moment now to finish setting up your account and unlock your full potential.\n\nWe're here if you need any help along the way!`,
      defaultCTA: "Complete Setup",
    },
    upsell: {
      name: "Upgrade Opportunity",
      defaultSubject: "Take Your Experience to the Next Level 🚀",
      defaultBody: `You've been doing great so far!\n\nBased on your activity, we think you're ready to unlock even more powerful features with our premium plan.\n\nHere's what you'll get when you upgrade:\n• Advanced tools and capabilities\n• Priority support\n• Exclusive premium content\n• And much more!\n\nUpgrade today and see the difference it makes.`,
      defaultCTA: "Upgrade Now",
    },
    "abandon-cart": {
      name: "Cart Reminder",
      defaultSubject: "You Left Something Behind! 🛒",
      defaultBody: `Hey there!\n\nWe noticed you left some items in your cart. We've saved them for you, but they won't last forever.\n\nYour items are waiting:\n• Quality products you selected\n• Special pricing still available\n• Fast shipping options\n\nComplete your purchase now before items sell out or prices change.\n\nNeed help deciding? Our team is here to answer any questions you might have!`,
      defaultCTA: "Complete Purchase",
    },
    reactivation: {
      name: "We Miss You!",
      defaultSubject: "We'd Love to See You Again! 💙",
      defaultBody: `It's been a while!\n\nWe've noticed you haven't been around lately, and we wanted to reach out. We miss having you as an active member of our community.\n\nA lot has changed since you were last here:\n• New features and improvements\n• Fresh content and resources\n• Better tools to help you succeed\n\nCome back and see what you've been missing. We'd love to have you back!\n\nYour account is still active and ready whenever you are.`,
      defaultCTA: "Welcome Back",
    },
  };

  const config = blockConfig[type] || blockConfig.welcome;

  // Apply tone variations to the body
  let bodyWithTone = config.defaultBody;

  switch(tone) {
    case 'professional':
      bodyWithTone = bodyWithTone.replace(/Hi there!/g, 'Greetings')
        .replace(/We're thrilled/g, 'We are pleased')
        .replace(/!/g, '.');
      break;
    case 'casual':
      bodyWithTone = bodyWithTone.replace(/Hello/g, 'Hey')
        .replace(/We are/g, "We're")
        .replace(/do not/g, "don't");
      break;
    case 'persuasive':
      bodyWithTone = bodyWithTone + "\n\nThis is a limited-time opportunity you won't want to miss!";
      break;
    case 'urgent':
      bodyWithTone = "⚡ TIME SENSITIVE ⚡\n\n" + bodyWithTone + "\n\nAct now before it's too late!";
      break;
  }

  // Incorporate user answers if provided
  if (answers && Object.keys(answers).length > 0) {
    const answersText = Object.values(answers).filter(a => a?.trim()).join('. ');
    if (answersText) {
      bodyWithTone = `Based on your interests in ${answersText.toLowerCase()}, here's something special for you:\n\n` + bodyWithTone;
    }
  }

  return {
    name: config.name,
    subject_line: customSubject || config.defaultSubject,
    preview_text: `Preview: ${config.defaultSubject.substring(0, 50)}...`,
    body_copy: bodyWithTone,
    cta_text: customCTA || config.defaultCTA,
    cta_url: "https://example.com",
  };
}

// Generate AI content for email blocks (using programmatic sample content)
app.post(
  "/api/ai/generate-content",
  mochaAuthMiddleware,
  zValidator("json", GenerateContentSchema),
  async (c) => {
    const db = c.env.DB;
    const user = c.get("user");
    const body = c.req.valid("json");

    console.log("[AI Generation] Request received:", {
      userId: user?.id,
      blockType: body.type,
      tone: body.tone,
    });

    if (!user) {
      console.error("[AI Generation] No user found in request");
      return c.json({ error: "Unauthorized" }, 401);
    }

    // Get or create user credits record
    let userCredits = await db
      .prepare("SELECT * FROM user_credits WHERE user_id = ?")
      .bind(user.id)
      .first();

    if (!userCredits) {
      // Initialize credits for new user
      const now = new Date().toISOString();
      await db
        .prepare(
          `
      INSERT INTO user_credits (user_id, credits_balance, total_credits_used, last_updated, email)
      VALUES (?, 10000, 0, ?, ?)
    `
        )
        .bind(user.id, now, user.email)
        .run();

      userCredits = await db
        .prepare("SELECT * FROM user_credits WHERE user_id = ?")
        .bind(user.id)
        .first();
    }

    // Check if user has enough credits (estimate ~1500 credits per generation)
    const estimatedCost = 1500;
    if ((userCredits?.credits_balance as number) < estimatedCost) {
      return c.json(
        {
          error: "Insufficient AI Credits",
          credits_balance: userCredits?.credits_balance,
          credits_needed: estimatedCost,
          message:
            "You don't have enough AI credits to generate content. Please upgrade your plan or purchase more credits.",
        },
        403
      );
    }

    try {
      console.log("[AI Generation] Generating sample content programmatically");

      // Generate sample content programmatically instead of using OpenAI
      const generatedContent = generateSampleContent(
        body.type,
        body.tone,
        body.answers || {},
        body.custom_subject,
        body.custom_cta
      );

      // Calculate credits used based on word count (5 credits per word generated)
      const wordCount = [
        generatedContent.name,
        generatedContent.subject_line,
        generatedContent.preview_text,
        generatedContent.body_copy,
        generatedContent.cta_text,
      ]
        .join(" ")
        .split(/\s+/)
        .filter((word) => word.length > 0).length;

      const creditsUsed = Math.max(50, wordCount * 5); // Minimum 50 credits, 5 credits per word

      // Deduct credits
      const now = new Date().toISOString();
      await db
        .prepare(
          `
      UPDATE user_credits
      SET credits_balance = credits_balance - ?,
          total_credits_used = total_credits_used + ?,
          last_updated = ?
      WHERE user_id = ?
    `
        )
        .bind(creditsUsed, creditsUsed, now, user.id)
        .run();

      console.log("[AI Generation] Credits deducted:", {
        wordCount,
        creditsUsed,
        userId: user.id,
      });

      console.log("[AI Generation] Returning generated content");
      return c.json({
        ...generatedContent,
        credits_used: creditsUsed,
        word_count: wordCount,
      });
    } catch (error: any) {
      console.error("[AI Generation] Error details:", {
        message: error?.message,
        name: error?.name,
        stack: error?.stack?.split("\n").slice(0, 3),
      });

      return c.json(
        {
          error: "Failed to generate content",
          details: error?.message || "Unknown error occurred",
        },
        500
      );
    }
  }
);

// Helper function to rewrite content with different tone
function rewriteContentWithTone(content: any, tone: string) {
  let { subject_line, preview_text, body_copy, cta_text } = content;

  switch(tone) {
    case 'professional':
      subject_line = subject_line.replace(/!/g, '.').replace(/🎉|🎁|⏰|🚀|🛒|💙/g, '');
      body_copy = body_copy
        .replace(/Hi there/g, 'Greetings')
        .replace(/Hey/g, 'Hello')
        .replace(/We're/g, 'We are')
        .replace(/don't/g, 'do not')
        .replace(/!/g, '.');
      cta_text = cta_text.replace(/!/g, '');
      break;

    case 'friendly':
      if (!subject_line.includes('!')) subject_line += '!';
      body_copy = body_copy.replace(/Greetings/g, 'Hi there');
      break;

    case 'casual':
      body_copy = body_copy
        .replace(/Greetings/g, 'Hey')
        .replace(/We are/g, "We're")
        .replace(/do not/g, "don't");
      break;

    case 'persuasive':
      subject_line = "Don't Miss Out: " + subject_line;
      body_copy = body_copy + "\n\nThis opportunity is too good to pass up. Join thousands of satisfied customers who've already taken action!";
      cta_text = cta_text + " - Limited Time";
      break;

    case 'urgent':
      subject_line = "⚡ URGENT: " + subject_line;
      body_copy = "⏰ TIME SENSITIVE ⏰\n\n" + body_copy + "\n\n🚨 Don't wait - act now before this opportunity expires!";
      cta_text = "Act Now - " + cta_text;
      break;
  }

  return {
    subject_line,
    preview_text: preview_text || `Preview: ${subject_line.substring(0, 50)}...`,
    body_copy,
    cta_text,
  };
}

// Rewrite email content with different tone (using programmatic approach)
app.post("/api/ai/rewrite-content", mochaAuthMiddleware, async (c) => {
  const user = c.get("user");
  const body = await c.req.json();

  if (!user) {
    return c.json({ error: "Unauthorized" }, 401);
  }

  try {
    // Rewrite content programmatically based on tone
    const rewrittenContent = rewriteContentWithTone(body, body.tone);

    // Calculate word count for demonstration (no credits deducted for rewrite)
    const wordCount = [
      rewrittenContent.subject_line || "",
      rewrittenContent.preview_text || "",
      rewrittenContent.body_copy || "",
      rewrittenContent.cta_text || "",
    ]
      .join(" ")
      .split(/\s+/)
      .filter((word) => word.length > 0).length;

    console.log("[AI Rewrite] Content rewritten:", {
      wordCount,
      userId: user.id,
    });

    return c.json(rewrittenContent);
  } catch (error) {
    console.error("AI rewrite error:", error);
    return c.json({ error: "Failed to rewrite content" }, 500);
  }
});

// ===== EXPORT ROUTES =====

// Export sequence
app.post(
  "/api/sequences/:id/export",
  mochaAuthMiddleware,
  zValidator("json", ExportSequenceSchema),
  async (c) => {
    const db = c.env.DB;
    const user = c.get("user");
    const sequenceId = c.req.param("id");
    const body = c.req.valid("json");
    const exportId = uuidv4();
    const now = new Date().toISOString();

    if (!user) {
      return c.json({ error: "Unauthorized" }, 401);
    }

    // Verify sequence ownership
    const sequence = await db
      .prepare("SELECT * FROM sequences WHERE id = ? AND user_id = ?")
      .bind(sequenceId, user.id)
      .first();

    if (!sequence) {
      return c.json({ error: "Sequence not found" }, 404);
    }

    const blocks = await db
      .prepare(
        "SELECT * FROM email_blocks WHERE sequence_id = ? ORDER BY send_delay_hours ASC"
      )
      .bind(sequenceId)
      .all();
    const connections = await db
      .prepare("SELECT * FROM sequence_connections WHERE sequence_id = ?")
      .bind(sequenceId)
      .all();

    // Track export
    await db
      .prepare(
        `
    INSERT INTO sequence_exports (id, sequence_id, user_id, export_type, export_format, created_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `
      )
      .bind(exportId, sequenceId, user.id, body.format, body.format, now)
      .run();

    let exportData;

    switch (body.format) {
      case "csv":
        const csvHeaders = [
          "Email #",
          "Type",
          "Name",
          "Subject Line",
          "Preview Text",
          "Email Body",
          "Send Delay (Hours)",
          "CTA Text",
          "CTA URL",
        ];
        const csvRows = (blocks.results as any[]).map((block, index) => [
          index + 1,
          block.type,
          block.name || "",
          block.subject_line || "",
          block.preview_text || "",
          block.body_copy || "",
          block.send_delay_hours || 0,
          block.cta_text || "",
          block.cta_url || "",
        ]);

        // Add UTF-8 BOM for proper Excel emoji rendering
        exportData =
          "\uFEFF" +
          [csvHeaders, ...csvRows]
            .map((row) =>
              row
                .map((cell) => `"${String(cell).replace(/"/g, '""')}"`)
                .join(",")
            )
            .join("\n");
        break;

      case "txt":
        exportData = (blocks.results as any[])
          .map(
            (block, index) =>
              `Email ${index + 1}: ${block.name}\n` +
              `Type: ${block.type}\n` +
              `Send Delay: ${block.send_delay_hours || 0} hours\n` +
              `Subject: ${block.subject_line || "No subject"}\n` +
              `Preview: ${block.preview_text || "No preview"}\n` +
              `Body: ${block.body_copy || "No content"}\n` +
              `CTA: ${block.cta_text || "No CTA"} (${
                block.cta_url || "No URL"
              })\n` +
              `${"=".repeat(50)}\n`
          )
          .join("\n");
        break;

      case "html":
        exportData = (blocks.results as any[])
          .map(
            (block, index) =>
              `<div style="border: 1px solid #ddd; margin: 20px 0; padding: 20px; border-radius: 8px;">` +
              `<h3>Email ${index + 1}: ${block.name}</h3>` +
              `<p><strong>Type:</strong> ${block.type}</p>` +
              `<p><strong>Send Delay:</strong> ${
                block.send_delay_hours || 0
              } hours</p>` +
              `<p><strong>Subject:</strong> ${
                block.subject_line || "No subject"
              }</p>` +
              `<p><strong>Preview:</strong> ${
                block.preview_text || "No preview"
              }</p>` +
              `<div><strong>Body:</strong><br>${(
                block.body_copy || "No content"
              ).replace(/\n/g, "<br>")}</div>` +
              `<p><strong>CTA:</strong> <a href="${block.cta_url || "#"}">${
                block.cta_text || "No CTA"
              }</a></p>` +
              `</div>`
          )
          .join("");
        break;

      case "json":
        exportData = JSON.stringify(
          {
            sequence,
            blocks: blocks.results,
            connections: connections.results,
            exported_at: now,
          },
          null,
          2
        );
        break;

      default:
        return c.json({ error: "Unsupported export format" }, 400);
    }

    return c.json({
      data: exportData,
      filename: `${String(sequence.name).replace(
        /[^a-zA-Z0-9]/g,
        "_"
      )}_sequence.${body.format}`,
    });
  }
);

export default app;
