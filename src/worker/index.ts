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
import { getCookie } from "hono/cookie";
import { 
  CreateSequenceSchema, 
  CreateEmailBlockSchema, 
  UpdateEmailBlockSchema,
  CreateConnectionSchema,
  CreateTemplateSchema,
  ExportSequenceSchema,
  GenerateContentSchema
} from "@/shared/types";
import OpenAI from "openai";
import { v4 as uuidv4 } from "uuid";

const app = new Hono<{ Bindings: Env }>();

const ADMIN_SESSION_COOKIE_NAME = 'admin_session_token';

// Admin authentication middleware
const adminAuthMiddleware = async (c: any, next: any) => {
  const sessionToken = getCookie(c, ADMIN_SESSION_COOKIE_NAME);
  
  if (!sessionToken) {
    return c.json({ error: "Unauthorized" }, 401);
  }
  
  const db = c.env.DB;
  const session = await db.prepare(
    "SELECT * FROM admin_sessions WHERE token = ? AND expires_at > datetime('now')"
  ).bind(sessionToken).first();
  
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
  if (email === 'gotayjust@hotmail.com' && password === 'inderpalastra11') {
    // Create session
    const sessionId = uuidv4();
    const token = uuidv4();
    const now = new Date();
    const expiresAt = new Date(now.getTime() + 24 * 60 * 60 * 1000); // 24 hours
    
    await db.prepare(`
      INSERT INTO admin_sessions (id, admin_email, token, created_at, expires_at)
      VALUES (?, ?, ?, ?, ?)
    `).bind(sessionId, email, token, now.toISOString(), expiresAt.toISOString()).run();
    
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
    await db.prepare("DELETE FROM admin_sessions WHERE token = ?").bind(sessionToken).run();
  }
  
  setCookie(c, ADMIN_SESSION_COOKIE_NAME, '', {
    httpOnly: true,
    path: '/',
    sameSite: 'none',
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
    const userSequence = await db.prepare(
      "SELECT user_id, created_at FROM sequences WHERE user_id = ? ORDER BY created_at ASC LIMIT 1"
    ).bind(userId).first();
    
    // Use sequence creation date or credit record date
    const createdAt = userSequence?.created_at || creditsRecord.last_updated || new Date().toISOString();
    
    users.push({
      id: userId,
      email: creditsRecord.email || userId, // Use stored email from user_credits
      created_at: createdAt,
      user_id: userId,
      credits_balance: creditsRecord.credits_balance || 0,
      total_credits_used: creditsRecord.total_credits_used || 0,
      plan: creditsRecord.plan || 'Basic',
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
  await db.prepare(`
    UPDATE user_credits 
    SET credits_balance = ?, plan = ?, last_updated = ?
    WHERE user_id = ?
  `).bind(body.credits_balance, body.plan, now, userId).run();
  
  // Note: Email changes would require integration with Mocha's user service
  // For now, we'll skip email updates
  
  return c.json({ success: true });
});

// Toggle user active status (admin only)
app.post("/api/admin/users/:userId/toggle-active", adminAuthMiddleware, async (c) => {
  const db = c.env.DB;
  const userId = c.req.param("userId");
  const now = new Date().toISOString();
  
  // Get current status
  const credits = await db.prepare(
    "SELECT is_active FROM user_credits WHERE user_id = ?"
  ).bind(userId).first();
  
  const newStatus = !(credits?.is_active !== false);
  
  await db.prepare(`
    UPDATE user_credits 
    SET is_active = ?, last_updated = ?
    WHERE user_id = ?
  `).bind(newStatus, now, userId).run();
  
  return c.json({ success: true });
});

// ===== AUTH ROUTES =====

// Get OAuth redirect URL
app.get('/api/oauth/google/redirect_url', async (c) => {
  const redirectUrl = await getOAuthRedirectUrl('google', {
    apiUrl: c.env.MOCHA_USERS_SERVICE_API_URL,
    apiKey: c.env.MOCHA_USERS_SERVICE_API_KEY,
  });

  return c.json({ redirectUrl }, 200);
});

// Exchange code for session token
app.post("/api/sessions", async (c) => {
  const body = await c.req.json();

  if (!body.code) {
    return c.json({ error: "No authorization code provided" }, 400);
  }

  const sessionToken = await exchangeCodeForSessionToken(body.code, {
    apiUrl: c.env.MOCHA_USERS_SERVICE_API_URL,
    apiKey: c.env.MOCHA_USERS_SERVICE_API_KEY,
  });

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
app.get("/api/users/me", authMiddleware, async (c) => {
  return c.json(c.get("user"));
});

// Get user credits
app.get("/api/users/me/credits", authMiddleware, async (c) => {
  const db = c.env.DB;
  const user = c.get("user");
  
  if (!user) {
    return c.json({ error: "Unauthorized" }, 401);
  }
  
  // Get or create user credits record
  let userCredits = await db.prepare(
    "SELECT * FROM user_credits WHERE user_id = ?"
  ).bind(user.id).first();
  
  const now = new Date().toISOString();
  
  if (!userCredits) {
    // Initialize credits for new user
    await db.prepare(`
      INSERT INTO user_credits (user_id, credits_balance, total_credits_used, last_updated, email)
      VALUES (?, 10000, 0, ?, ?)
    `).bind(user.id, now, user.email).run();
    
    userCredits = await db.prepare(
      "SELECT * FROM user_credits WHERE user_id = ?"
    ).bind(user.id).first();
  } else {
    // Update email if it's missing or different (sync with auth service)
    if (!userCredits.email || userCredits.email !== user.email) {
      await db.prepare(`
        UPDATE user_credits 
        SET email = ?, last_updated = ?
        WHERE user_id = ?
      `).bind(user.email, now, user.id).run();
      
      userCredits = await db.prepare(
        "SELECT * FROM user_credits WHERE user_id = ?"
      ).bind(user.id).first();
    }
  }
  
  return c.json(userCredits);
});

// Logout
app.get('/api/logout', async (c) => {
  const sessionToken = getCookie(c, MOCHA_SESSION_TOKEN_COOKIE_NAME);

  if (typeof sessionToken === 'string') {
    await deleteSession(sessionToken, {
      apiUrl: c.env.MOCHA_USERS_SERVICE_API_URL,
      apiKey: c.env.MOCHA_USERS_SERVICE_API_KEY,
    });
  }

  setCookie(c, MOCHA_SESSION_TOKEN_COOKIE_NAME, '', {
    httpOnly: true,
    path: '/',
    sameSite: 'none',
    secure: true,
    maxAge: 0,
  });

  return c.json({ success: true }, 200);
});

// ===== SEQUENCE ROUTES =====

// Get all sequences for authenticated user
app.get("/api/sequences", authMiddleware, async (c) => {
  const db = c.env.DB;
  const user = c.get("user");
  
  if (!user) {
    return c.json({ error: "Unauthorized" }, 401);
  }
  
  const sequences = await db.prepare(
    "SELECT * FROM sequences WHERE user_id = ? ORDER BY created_at DESC"
  ).bind(user.id).all();
  
  return c.json(sequences.results);
});

// Create sequence
app.post("/api/sequences", authMiddleware, zValidator("json", CreateSequenceSchema), async (c) => {
  const db = c.env.DB;
  const user = c.get("user");
  const body = c.req.valid("json");
  const id = uuidv4();
  const now = new Date().toISOString();
  
  if (!user) {
    return c.json({ error: "Unauthorized" }, 401);
  }
  
  await db.prepare(`
    INSERT INTO sequences (id, name, description, user_id, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `).bind(id, body.name, body.description || "", user.id, now, now).run();
  
  const sequence = await db.prepare("SELECT * FROM sequences WHERE id = ?").bind(id).first();
  return c.json(sequence);
});

// Update sequence
app.put("/api/sequences/:id", authMiddleware, async (c) => {
  const db = c.env.DB;
  const user = c.get("user");
  const sequenceId = c.req.param("id");
  const body = await c.req.json();
  const now = new Date().toISOString();
  
  if (!user) {
    return c.json({ error: "Unauthorized" }, 401);
  }
  
  // Verify ownership
  const sequence = await db.prepare(
    "SELECT * FROM sequences WHERE id = ? AND user_id = ?"
  ).bind(sequenceId, user.id).first();
  
  if (!sequence) {
    return c.json({ error: "Sequence not found" }, 404);
  }
  
  // Validate input
  if (!body.name || !body.name.trim()) {
    return c.json({ error: "Name is required" }, 400);
  }
  
  // Update sequence
  await db.prepare(`
    UPDATE sequences SET name = ?, description = ?, updated_at = ? WHERE id = ?
  `).bind(body.name.trim(), body.description || "", now, sequenceId).run();
  
  const updatedSequence = await db.prepare("SELECT * FROM sequences WHERE id = ?").bind(sequenceId).first();
  return c.json(updatedSequence);
});

// Get sequence with blocks and connections
app.get("/api/sequences/:id", authMiddleware, async (c) => {
  const db = c.env.DB;
  const user = c.get("user");
  const sequenceId = c.req.param("id");
  
  if (!user) {
    return c.json({ error: "Unauthorized" }, 401);
  }
  
  const sequence = await db.prepare(
    "SELECT * FROM sequences WHERE id = ? AND user_id = ?"
  ).bind(sequenceId, user.id).first();
  
  if (!sequence) {
    return c.json({ error: "Sequence not found" }, 404);
  }
  
  const blocks = await db.prepare("SELECT * FROM email_blocks WHERE sequence_id = ?").bind(sequenceId).all();
  const connections = await db.prepare("SELECT * FROM sequence_connections WHERE sequence_id = ?").bind(sequenceId).all();
  
  return c.json({
    sequence,
    blocks: blocks.results,
    connections: connections.results
  });
});

// Delete sequence
app.delete("/api/sequences/:id", authMiddleware, async (c) => {
  const db = c.env.DB;
  const user = c.get("user");
  const sequenceId = c.req.param("id");
  
  if (!user) {
    return c.json({ error: "Unauthorized" }, 401);
  }
  
  // Verify ownership
  const sequence = await db.prepare(
    "SELECT * FROM sequences WHERE id = ? AND user_id = ?"
  ).bind(sequenceId, user.id).first();
  
  if (!sequence) {
    return c.json({ error: "Sequence not found" }, 404);
  }
  
  // Delete in order: connections, blocks, sequence
  await db.prepare("DELETE FROM sequence_connections WHERE sequence_id = ?").bind(sequenceId).run();
  await db.prepare("DELETE FROM email_blocks WHERE sequence_id = ?").bind(sequenceId).run();
  await db.prepare("DELETE FROM sequences WHERE id = ?").bind(sequenceId).run();
  
  return c.json({ success: true });
});

// Duplicate sequence
app.post("/api/sequences/:id/duplicate", authMiddleware, async (c) => {
  const db = c.env.DB;
  const user = c.get("user");
  const sequenceId = c.req.param("id");
  const newSequenceId = uuidv4();
  const now = new Date().toISOString();
  
  if (!user) {
    return c.json({ error: "Unauthorized" }, 401);
  }
  
  // Get original sequence
  const originalSequence = await db.prepare(
    "SELECT * FROM sequences WHERE id = ? AND user_id = ?"
  ).bind(sequenceId, user.id).first();
  
  if (!originalSequence) {
    return c.json({ error: "Sequence not found" }, 404);
  }
  
  // Duplicate sequence
  await db.prepare(`
    INSERT INTO sequences (id, name, description, user_id, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `).bind(
    newSequenceId, 
    `${String(originalSequence.name)} (Copy)`, 
    originalSequence.description, 
    user.id, 
    now, 
    now
  ).run();
  
  // Get original blocks
  const originalBlocks = await db.prepare("SELECT * FROM email_blocks WHERE sequence_id = ?").bind(sequenceId).all();
  const blockIdMap = new Map<string, string>();
  
  // Duplicate blocks
  for (const block of originalBlocks.results as any[]) {
    const newBlockId = uuidv4();
    blockIdMap.set(block.id, newBlockId);
    
    await db.prepare(`
      INSERT INTO email_blocks (id, sequence_id, type, name, subject_line, preview_text, body_copy, cta_text, cta_url, send_delay_hours, position_x, position_y, notes, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      newBlockId, newSequenceId, block.type, block.name, block.subject_line, block.preview_text,
      block.body_copy, block.cta_text, block.cta_url, block.send_delay_hours,
      block.position_x, block.position_y, block.notes, now, now
    ).run();
  }
  
  // Duplicate connections
  const originalConnections = await db.prepare("SELECT * FROM sequence_connections WHERE sequence_id = ?").bind(sequenceId).all();
  
  for (const connection of originalConnections.results as any[]) {
    const newConnectionId = uuidv4();
    const newSourceId = blockIdMap.get(connection.source_block_id);
    const newTargetId = blockIdMap.get(connection.target_block_id);
    
    if (newSourceId && newTargetId) {
      await db.prepare(`
        INSERT INTO sequence_connections (id, sequence_id, source_block_id, target_block_id, condition_type, custom_label, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(newConnectionId, newSequenceId, newSourceId, newTargetId, connection.condition_type, connection.custom_label || null, now, now).run();
    }
  }
  
  const newSequence = await db.prepare("SELECT * FROM sequences WHERE id = ?").bind(newSequenceId).first();
  return c.json(newSequence);
});

// ===== EMAIL BLOCK ROUTES =====

// Create email block
app.post("/api/sequences/:id/blocks", authMiddleware, zValidator("json", CreateEmailBlockSchema), async (c) => {
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
  const sequence = await db.prepare(
    "SELECT * FROM sequences WHERE id = ? AND user_id = ?"
  ).bind(sequenceId, user.id).first();
  
  if (!sequence) {
    return c.json({ error: "Sequence not found" }, 404);
  }
  
  await db.prepare(`
    INSERT INTO email_blocks (id, sequence_id, type, name, position_x, position_y, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(blockId, sequenceId, body.type, body.name, body.position_x, body.position_y, now, now).run();
  
  const block = await db.prepare("SELECT * FROM email_blocks WHERE id = ?").bind(blockId).first();
  return c.json(block);
});

// Update email block
app.put("/api/blocks/:id", authMiddleware, zValidator("json", UpdateEmailBlockSchema), async (c) => {
  const db = c.env.DB;
  const user = c.get("user");
  const blockId = c.req.param("id");
  const body = c.req.valid("json");
  const now = new Date().toISOString();
  
  if (!user) {
    return c.json({ error: "Unauthorized" }, 401);
  }
  
  // Verify block ownership through sequence
  const block = await db.prepare(`
    SELECT eb.* FROM email_blocks eb
    JOIN sequences s ON eb.sequence_id = s.id
    WHERE eb.id = ? AND s.user_id = ?
  `).bind(blockId, user.id).first();
  
  if (!block) {
    return c.json({ error: "Block not found" }, 404);
  }
  
  const updates = Object.entries(body).filter(([_, value]) => value !== undefined);
  if (updates.length === 0) {
    return c.json({ error: "No fields to update" }, 400);
  }
  
  const setClause = updates.map(([key, _]) => `${key} = ?`).join(", ");
  const values = [...updates.map(([_, value]) => value), now, blockId];
  
  await db.prepare(`
    UPDATE email_blocks SET ${setClause}, updated_at = ? WHERE id = ?
  `).bind(...values).run();
  
  const updatedBlock = await db.prepare("SELECT * FROM email_blocks WHERE id = ?").bind(blockId).first();
  return c.json(updatedBlock);
});

// Duplicate block
app.post("/api/blocks/:id/duplicate", authMiddleware, async (c) => {
  const db = c.env.DB;
  const user = c.get("user");
  const blockId = c.req.param("id");
  const newBlockId = uuidv4();
  const now = new Date().toISOString();
  
  if (!user) {
    return c.json({ error: "Unauthorized" }, 401);
  }
  
  // Fetch the source block from database to get latest content
  const sourceBlock = await db.prepare(`
    SELECT eb.* FROM email_blocks eb
    JOIN sequences s ON eb.sequence_id = s.id
    WHERE eb.id = ? AND s.user_id = ?
  `).bind(blockId, user.id).first();
  
  if (!sourceBlock) {
    return c.json({ error: "Block not found" }, 404);
  }
  
  // Calculate new position offset from original
  const newPositionX = (sourceBlock.position_x as number) + 350;
  const newPositionY = (sourceBlock.position_y as number) + 50;
  
  // Create new block with all content from source block
  await db.prepare(`
    INSERT INTO email_blocks (
      id, sequence_id, type, name, subject_line, preview_text, 
      body_copy, cta_text, cta_url, send_delay_hours, 
      position_x, position_y, notes, created_at, updated_at
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(
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
  ).run();
  
  // Return the newly created block
  const newBlock = await db.prepare("SELECT * FROM email_blocks WHERE id = ?").bind(newBlockId).first();
  return c.json(newBlock);
});

// Delete block
app.delete("/api/blocks/:id", authMiddleware, async (c) => {
  const db = c.env.DB;
  const user = c.get("user");
  const blockId = c.req.param("id");
  
  if (!user) {
    return c.json({ error: "Unauthorized" }, 401);
  }
  
  // Verify block ownership through sequence
  const block = await db.prepare(`
    SELECT eb.* FROM email_blocks eb
    JOIN sequences s ON eb.sequence_id = s.id
    WHERE eb.id = ? AND s.user_id = ?
  `).bind(blockId, user.id).first();
  
  if (!block) {
    return c.json({ error: "Block not found" }, 404);
  }
  
  // Delete connections first
  await db.prepare("DELETE FROM sequence_connections WHERE source_block_id = ? OR target_block_id = ?").bind(blockId, blockId).run();
  
  // Delete block
  await db.prepare("DELETE FROM email_blocks WHERE id = ?").bind(blockId).run();
  
  return c.json({ success: true });
});

// ===== CONNECTION ROUTES =====

// Create connection
app.post("/api/connections", authMiddleware, zValidator("json", CreateConnectionSchema), async (c) => {
  const db = c.env.DB;
  const user = c.get("user");
  const body = c.req.valid("json");
  const connectionId = uuidv4();
  const now = new Date().toISOString();
  
  if (!user) {
    return c.json({ error: "Unauthorized" }, 401);
  }
  
  // Verify sequence ownership
  const sequence = await db.prepare(
    "SELECT * FROM sequences WHERE id = ? AND user_id = ?"
  ).bind(body.sequence_id, user.id).first();
  
  if (!sequence) {
    return c.json({ error: "Sequence not found" }, 404);
  }
  
  await db.prepare(`
    INSERT INTO sequence_connections (id, sequence_id, source_block_id, target_block_id, condition_type, custom_label, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(connectionId, body.sequence_id, body.source_block_id, body.target_block_id, body.condition_type, body.custom_label || null, now, now).run();
  
  const connection = await db.prepare("SELECT * FROM sequence_connections WHERE id = ?").bind(connectionId).first();
  return c.json(connection);
});

// Delete connection
app.delete("/api/connections/:id", authMiddleware, async (c) => {
  const db = c.env.DB;
  const user = c.get("user");
  const connectionId = c.req.param("id");
  
  if (!user) {
    return c.json({ error: "Unauthorized" }, 401);
  }
  
  // Verify connection ownership through sequence
  const connection = await db.prepare(`
    SELECT sc.* FROM sequence_connections sc
    JOIN sequences s ON sc.sequence_id = s.id
    WHERE sc.id = ? AND s.user_id = ?
  `).bind(connectionId, user.id).first();
  
  if (!connection) {
    return c.json({ error: "Connection not found" }, 404);
  }
  
  await db.prepare("DELETE FROM sequence_connections WHERE id = ?").bind(connectionId).run();
  return c.json({ success: true });
});

// ===== TEMPLATE ROUTES =====

// Get public templates
app.get("/api/templates", async (c) => {
  const db = c.env.DB;
  const templates = await db.prepare(
    "SELECT * FROM sequence_templates WHERE is_public = TRUE ORDER BY created_at DESC"
  ).all();
  
  return c.json(templates.results);
});

// Get user's saved templates
app.get("/api/user-templates", authMiddleware, async (c) => {
  const db = c.env.DB;
  const user = c.get("user");
  
  if (!user) {
    return c.json({ error: "Unauthorized" }, 401);
  }
  
  const templates = await db.prepare(
    "SELECT * FROM user_templates WHERE user_id = ? ORDER BY created_at DESC"
  ).bind(user.id).all();
  
  return c.json(templates.results);
});

// Delete user template
app.delete("/api/user-templates/:id", authMiddleware, async (c) => {
  const db = c.env.DB;
  const user = c.get("user");
  const templateId = c.req.param("id");
  
  if (!user) {
    return c.json({ error: "Unauthorized" }, 401);
  }
  
  // Verify ownership
  const template = await db.prepare(
    "SELECT * FROM user_templates WHERE id = ? AND user_id = ?"
  ).bind(templateId, user.id).first();
  
  if (!template) {
    return c.json({ error: "Template not found" }, 404);
  }
  
  await db.prepare("DELETE FROM user_templates WHERE id = ?").bind(templateId).run();
  
  return c.json({ success: true });
});

// Save sequence as template
app.post("/api/sequences/:id/save-template", authMiddleware, zValidator("json", CreateTemplateSchema), async (c) => {
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
  const sequence = await db.prepare(
    "SELECT * FROM sequences WHERE id = ? AND user_id = ?"
  ).bind(sequenceId, user.id).first();
  
  if (!sequence) {
    return c.json({ error: "Sequence not found" }, 404);
  }
  
  const blocks = await db.prepare("SELECT * FROM email_blocks WHERE sequence_id = ?").bind(sequenceId).all();
  const connections = await db.prepare("SELECT * FROM sequence_connections WHERE sequence_id = ?").bind(sequenceId).all();
  
  const sequenceData = JSON.stringify({
    sequence,
    blocks: blocks.results,
    connections: connections.results
  });
  
  // Save to user_templates instead of sequence_templates for user's personal templates
  await db.prepare(`
    INSERT INTO user_templates (id, name, description, user_id, sequence_data, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).bind(templateId, body.name, body.description || "", user.id, sequenceData, now, now).run();
  
  const template = await db.prepare("SELECT * FROM user_templates WHERE id = ?").bind(templateId).first();
  return c.json(template);
});

// ===== AI CONTENT GENERATION =====

// Generate AI content for email blocks
app.post("/api/ai/generate-content", authMiddleware, zValidator("json", GenerateContentSchema), async (c) => {
  const db = c.env.DB;
  const user = c.get("user");
  const body = c.req.valid("json");

  console.log('[AI Generation] Request received:', { 
    userId: user?.id, 
    blockType: body.type, 
    tone: body.tone 
  });

  if (!user) {
    console.error('[AI Generation] No user found in request');
    return c.json({ error: "Unauthorized" }, 401);
  }
  
  // Get or create user credits record
  let userCredits = await db.prepare(
    "SELECT * FROM user_credits WHERE user_id = ?"
  ).bind(user.id).first();
  
  if (!userCredits) {
    // Initialize credits for new user
    const now = new Date().toISOString();
    await db.prepare(`
      INSERT INTO user_credits (user_id, credits_balance, total_credits_used, last_updated, email)
      VALUES (?, 10000, 0, ?, ?)
    `).bind(user.id, now, user.email).run();
    
    userCredits = await db.prepare(
      "SELECT * FROM user_credits WHERE user_id = ?"
    ).bind(user.id).first();
  }
  
  // Check if user has enough credits (estimate ~1500 credits per generation)
  const estimatedCost = 1500;
  if ((userCredits?.credits_balance as number) < estimatedCost) {
    return c.json({ 
      error: "Insufficient AI Credits",
      credits_balance: userCredits?.credits_balance,
      credits_needed: estimatedCost,
      message: "You don't have enough AI credits to generate content. Please upgrade your plan or purchase more credits."
    }, 403);
  }

  const openaiKey = c.env.OPENAI_API_KEY;
  console.log('[AI Generation] OpenAI key check:', { 
    hasKey: !!openaiKey, 
    keyPrefix: openaiKey ? openaiKey.substring(0, 10) + '...' : 'none' 
  });
  
  if (!openaiKey) {
    console.error('[AI Generation] OpenAI API key not configured');
    return c.json({ error: "OpenAI API key not configured" }, 500);
  }

  try {
    const client = new OpenAI({
      apiKey: openaiKey,
    });
    console.log('[AI Generation] OpenAI client created successfully');

    // Build context-aware prompt based on block type and answers
    const blockConfig = {
      welcome: "welcome email that introduces new subscribers",
      "follow-up": "follow-up email that nurtures leads",
      offer: "promotional email with a special offer",
      reminder: "reminder email to encourage action",
      upsell: "upsell email to promote upgrades",
      "abandon-cart": "cart abandonment recovery email",
      reactivation: "re-engagement email for inactive subscribers"
    };

    let prompt = `Create a ${blockConfig[body.type]} with the following details:\n`;
    
    if (body.answers && Object.keys(body.answers).length > 0) {
      prompt += Object.entries(body.answers).map(([, value]) => `- ${value}`).join('\n') + '\n\n';
    }
    
    if (body.custom_subject) {
      prompt += `Use this subject line: "${body.custom_subject}"\n`;
    }
    
    if (body.custom_cta) {
      prompt += `Use this call-to-action: "${body.custom_cta}"\n`;
    }

    prompt += `Tone: ${body.tone}

Please generate:
1. A compelling email name/title
2. ${body.custom_subject ? 'Keep the provided subject line as is' : 'An attention-grabbing subject line'}
3. Preview text that complements the subject
4. Email body copy (2-3 paragraphs, personable and ${body.tone})
5. ${body.custom_cta ? 'Keep the provided CTA text as is' : 'Call-to-action button text'}
6. A relevant URL placeholder

Format as JSON with keys: name, subject_line, preview_text, body_copy, cta_text, cta_url`;

    console.log('[AI Generation] Calling OpenAI API...');
    const response = await client.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [
        {
          role: "system",
          content: "You are an expert email marketing copywriter. Create compelling, conversion-focused email content that matches the requested tone and purpose. Always respond with valid JSON."
        },
        {
          role: "user",
          content: prompt
        }
      ],
      response_format: { type: "json_object" },
      temperature: 0.7,
    });

    console.log('[AI Generation] OpenAI API call successful');
    console.log('[AI Generation] Response content length:', response.choices[0].message.content?.length || 0);

    const content = JSON.parse(response.choices[0].message.content || '{}');
    console.log('[AI Generation] Parsed content keys:', Object.keys(content));
    
    // Ensure all required fields are present
    const generatedContent = {
      name: content.name || `${blockConfig[body.type]} Email`,
      subject_line: body.custom_subject || content.subject_line || "Your subject line here",
      preview_text: content.preview_text || "Preview text here",
      body_copy: content.body_copy || "Email content here",
      cta_text: body.custom_cta || content.cta_text || "Click Here",
      cta_url: content.cta_url || "https://example.com"
    };

    // Calculate credits used based on word count (5 credits per word generated)
    const wordCount = [
      generatedContent.name,
      generatedContent.subject_line,
      generatedContent.preview_text,
      generatedContent.body_copy,
      generatedContent.cta_text
    ].join(' ').split(/\s+/).filter(word => word.length > 0).length;
    
    const creditsUsed = Math.max(50, wordCount * 5); // Minimum 50 credits, 5 credits per word
    
    // Deduct credits
    const now = new Date().toISOString();
    await db.prepare(`
      UPDATE user_credits 
      SET credits_balance = credits_balance - ?, 
          total_credits_used = total_credits_used + ?,
          last_updated = ?
      WHERE user_id = ?
    `).bind(creditsUsed, creditsUsed, now, user.id).run();
    
    console.log('[AI Generation] Credits deducted:', { 
      wordCount, 
      creditsUsed,
      userId: user.id 
    });

    console.log('[AI Generation] Returning generated content');
    return c.json({
      ...generatedContent,
      credits_used: creditsUsed,
      word_count: wordCount
    });
  } catch (error: any) {
    console.error('[AI Generation] Error details:', {
      message: error?.message,
      name: error?.name,
      status: error?.status,
      type: error?.type,
      code: error?.code,
      stack: error?.stack?.split('\n').slice(0, 3)
    });
    
    // Return more specific error message
    const errorMessage = error?.message || 'Unknown error occurred';
    return c.json({ 
      error: "Failed to generate content", 
      details: errorMessage,
      hint: "Check server logs for more information"
    }, 500);
  }
});

// Rewrite email content with different tone
app.post("/api/ai/rewrite-content", authMiddleware, async (c) => {
  const db = c.env.DB;
  const user = c.get("user");
  const body = await c.req.json();

  if (!user) {
    return c.json({ error: "Unauthorized" }, 401);
  }
  
  // Get or create user credits record
  let userCredits = await db.prepare(
    "SELECT * FROM user_credits WHERE user_id = ?"
  ).bind(user.id).first();
  
  if (!userCredits) {
    // Initialize credits for new user
    const now = new Date().toISOString();
    await db.prepare(`
      INSERT INTO user_credits (user_id, credits_balance, total_credits_used, last_updated, email)
      VALUES (?, 10000, 0, ?, ?)
    `).bind(user.id, now, user.email).run();
    
    userCredits = await db.prepare(
      "SELECT * FROM user_credits WHERE user_id = ?"
    ).bind(user.id).first();
  }
  
  // Check if user has enough credits (estimate ~800 credits per rewrite)
  const estimatedCost = 800;
  if ((userCredits?.credits_balance as number) < estimatedCost) {
    return c.json({ 
      error: "Insufficient AI Credits",
      credits_balance: userCredits?.credits_balance,
      credits_needed: estimatedCost,
      message: "You don't have enough AI credits to rewrite content. Please upgrade your plan or purchase more credits."
    }, 403);
  }

  const openaiKey = (c.env as any).OPENAI_API_KEY;
  if (!openaiKey) {
    return c.json({ error: "OpenAI API key not configured" }, 500);
  }

  try {
    const client = new OpenAI({
      apiKey: openaiKey,
    });

    const prompt = `Rewrite this email content with a ${body.tone} tone:

Subject: ${body.subject_line}
Preview: ${body.preview_text}
Body: ${body.body_copy}
CTA: ${body.cta_text}

Keep the same core message but adjust the tone to be more ${body.tone}. Format as JSON with keys: subject_line, preview_text, body_copy, cta_text`;

    const response = await client.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [
        {
          role: "system",
          content: "You are an expert email copywriter. Rewrite email content to match the requested tone while preserving the core message and call-to-action. Always respond with valid JSON."
        },
        {
          role: "user",
          content: prompt
        }
      ],
      response_format: { type: "json_object" },
      temperature: 0.7,
    });

    const content = JSON.parse(response.choices[0].message.content || '{}');
    
    // Calculate credits used based on word count (5 credits per word generated)
    const wordCount = [
      content.subject_line || '',
      content.preview_text || '',
      content.body_copy || '',
      content.cta_text || ''
    ].join(' ').split(/\s+/).filter(word => word.length > 0).length;
    
    const creditsUsed = Math.max(50, wordCount * 5); // Minimum 50 credits, 5 credits per word
    
    // Deduct credits
    const now = new Date().toISOString();
    await db.prepare(`
      UPDATE user_credits 
      SET credits_balance = credits_balance - ?, 
          total_credits_used = total_credits_used + ?,
          last_updated = ?
      WHERE user_id = ?
    `).bind(creditsUsed, creditsUsed, now, user.id).run();
    
    console.log('[AI Rewrite] Credits deducted:', { 
      wordCount, 
      creditsUsed,
      userId: user.id 
    });
    
    return c.json({
      ...content,
      credits_used: creditsUsed,
      word_count: wordCount
    });
  } catch (error) {
    console.error('AI rewrite error:', error);
    return c.json({ error: "Failed to rewrite content" }, 500);
  }
});

// ===== EXPORT ROUTES =====

// Export sequence
app.post("/api/sequences/:id/export", authMiddleware, zValidator("json", ExportSequenceSchema), async (c) => {
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
  const sequence = await db.prepare(
    "SELECT * FROM sequences WHERE id = ? AND user_id = ?"
  ).bind(sequenceId, user.id).first();
  
  if (!sequence) {
    return c.json({ error: "Sequence not found" }, 404);
  }
  
  const blocks = await db.prepare("SELECT * FROM email_blocks WHERE sequence_id = ? ORDER BY send_delay_hours ASC").bind(sequenceId).all();
  const connections = await db.prepare("SELECT * FROM sequence_connections WHERE sequence_id = ?").bind(sequenceId).all();
  
  // Track export
  await db.prepare(`
    INSERT INTO sequence_exports (id, sequence_id, user_id, export_type, export_format, created_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `).bind(exportId, sequenceId, user.id, body.format, body.format, now).run();
  
  let exportData;
  
  switch (body.format) {
    case 'csv':
      const csvHeaders = ['Email #', 'Type', 'Name', 'Subject Line', 'Preview Text', 'Email Body', 'Send Delay (Hours)', 'CTA Text', 'CTA URL'];
      const csvRows = (blocks.results as any[]).map((block, index) => [
        index + 1,
        block.type,
        block.name || '',
        block.subject_line || '',
        block.preview_text || '',
        block.body_copy || '',
        block.send_delay_hours || 0,
        block.cta_text || '',
        block.cta_url || ''
      ]);
      
      // Add UTF-8 BOM for proper Excel emoji rendering
      exportData = '\uFEFF' + [csvHeaders, ...csvRows].map(row => 
        row.map(cell => `"${String(cell).replace(/"/g, '""')}"`).join(',')
      ).join('\n');
      break;
      
    case 'txt':
      exportData = (blocks.results as any[]).map((block, index) => 
        `Email ${index + 1}: ${block.name}\n` +
        `Type: ${block.type}\n` +
        `Send Delay: ${block.send_delay_hours || 0} hours\n` +
        `Subject: ${block.subject_line || 'No subject'}\n` +
        `Preview: ${block.preview_text || 'No preview'}\n` +
        `Body: ${block.body_copy || 'No content'}\n` +
        `CTA: ${block.cta_text || 'No CTA'} (${block.cta_url || 'No URL'})\n` +
        `${'='.repeat(50)}\n`
      ).join('\n');
      break;
      
    case 'html':
      exportData = (blocks.results as any[]).map((block, index) => 
        `<div style="border: 1px solid #ddd; margin: 20px 0; padding: 20px; border-radius: 8px;">` +
        `<h3>Email ${index + 1}: ${block.name}</h3>` +
        `<p><strong>Type:</strong> ${block.type}</p>` +
        `<p><strong>Send Delay:</strong> ${block.send_delay_hours || 0} hours</p>` +
        `<p><strong>Subject:</strong> ${block.subject_line || 'No subject'}</p>` +
        `<p><strong>Preview:</strong> ${block.preview_text || 'No preview'}</p>` +
        `<div><strong>Body:</strong><br>${(block.body_copy || 'No content').replace(/\n/g, '<br>')}</div>` +
        `<p><strong>CTA:</strong> <a href="${block.cta_url || '#'}">${block.cta_text || 'No CTA'}</a></p>` +
        `</div>`
      ).join('');
      break;
      
    case 'json':
      exportData = JSON.stringify({
        sequence,
        blocks: blocks.results,
        connections: connections.results,
        exported_at: now
      }, null, 2);
      break;
      
    default:
      return c.json({ error: "Unsupported export format" }, 400);
  }
  
  return c.json({ 
    data: exportData,
    filename: `${String(sequence.name).replace(/[^a-zA-Z0-9]/g, '_')}_sequence.${body.format}`
  });
});

export default app;
