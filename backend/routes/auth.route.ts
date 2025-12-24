import { Router, Request, Response } from "express";
import bcrypt from "bcryptjs";
import { dbRun, dbGet, dbAll } from "../utils/db";
import { authenticateToken, generateToken } from "../middleware/auth.middleware";
import { loginLimiter, registerLimiter } from "../middleware/rateLimiter.middleware";
import { registerSchema, loginSchema } from "../utils/validation";
import { User, Session } from "../types";
import logger from "../utils/logger";

const router = Router();

// @router  POST /api/auth/register
// @desc    Register a new user
// @access  Public
router.post("/register", registerLimiter, async (req: Request, res: Response): Promise<void> => {
  try {
    // Validate input
    const validation = registerSchema.safeParse(req.body);
    if (!validation.success) {
      const errorMessage = validation.error.issues[0].message;
      logger.warn(`Registration validation failed: ${errorMessage}`);
      res.status(400).json({ message: errorMessage });
      return;
    }

    const { email, password } = validation.data;

    // Check if user already exists
    const existingUser = await dbGet<User>("SELECT * FROM users WHERE email = ?", [email]);
    if (existingUser) {
      logger.warn(`Registration attempt with existing email: ${email}`);
      res.status(400).json({ message: "User with this email already exists" });
      return;
    }

    // Create user
    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);

    const result = await dbRun("INSERT INTO users (email, password_hash) VALUES (?, ?)", [
      email,
      passwordHash,
    ]);

    logger.info(`New user registered: ${email} (ID: ${result.lastID})`);
    res.status(201).json({
      message: "User registered successfully",
      userId: result.lastID,
    });
  } catch (error) {
    logger.error("Registration error:", error);
    res.status(500).json({ message: "Server error during registration" });
  }
});

// @router  POST /api/auth/login
// @desc    Authenticate user and return JWT token
// @access  Public
router.post("/login", loginLimiter, async (req: Request, res: Response): Promise<void> => {
  try {
    // Validate input
    const validation = loginSchema.safeParse(req.body);
    if (!validation.success) {
      const errorMessage = validation.error.issues[0].message;
      logger.warn(`Login validation failed: ${errorMessage}`);
      res.status(400).json({ message: errorMessage });
      return;
    }

    const { email, password } = validation.data;

    // Check if user exists
    const user = await dbGet<User>("SELECT * FROM users WHERE email = ?", [email]);
    if (!user) {
      logger.warn(`Login attempt with non-existent email: ${email}`);
      res.status(401).json({ message: "Invalid credentials" });
      return;
    }

    // Check if password is matched
    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) {
      logger.warn(`Failed login attempt for user: ${email}`);
      res.status(401).json({ message: "Invalid credentials" });
      return;
    }

    // Create session
    const device = (req.headers["x-device"] as string) || "Unknown";
    const ip = req.ip || req.socket.remoteAddress || "Unknown";
    const userAgent = req.headers["user-agent"] || "Unknown";
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(); // 7 days

    const sessionResult = await dbRun(
      "INSERT INTO sessions (user_id, device, ip, user_agent, expires_at) VALUES (?, ?, ?, ?, ?)",
      [user.id, device, ip, userAgent, expiresAt],
    );

    // Generate token with session ID
    const token = generateToken({
      id: user.id,
      email: user.email,
      sessionId: sessionResult.lastID,
    });

    logger.info(`User logged in successfully: ${email} (Session: ${sessionResult.lastID})`);
    res.json({
      message: "Logged in successfully",
      token,
      user: {
        id: user.id,
        email: user.email,
      },
    });
  } catch (error) {
    logger.error("Login error:", error);
    res.status(500).json({ message: "Server error during login" });
  }
});

// @router  POST /api/auth/logout
// @desc    Logout user (invalidate token - client-side removal)
// @access  Private
router.post("/logout", authenticateToken, async (req: Request, res: Response): Promise<void> => {
  try {
    // For now, logout is handled client-side by removing the token
    // In future: implement refresh token rotation and session tracking
    // to properly invalidate tokens server-side

    logger.info(`User logged out: ${req.user?.email}`);
    res.json({
      message: "Logout successful",
      user: req.user,
    });
  } catch (error) {
    logger.error("Logout error:", error);
    res.status(500).json({ message: "Server error during logout" });
  }
});

// @router  GET /api/auth/sessions
// @desc    Get all active sessions for the authenticated user
// @access  Private
router.get("/sessions", authenticateToken, async (req: Request, res: Response): Promise<void> => {
  try {
    const userId = req.user?.id;

    const sessions = await dbAll<Session>(
      "SELECT id, device, ip, user_agent, created_at, expires_at FROM sessions WHERE user_id = ? AND expires_at > datetime('now')",
      [userId],
    );

    logger.info(`User ${req.user?.email} fetched ${sessions.length} active sessions`);
    res.json({
      sessions: sessions.map((session) => ({
        id: session.id,
        device: session.device,
        ip: session.ip,
        userAgent: session.user_agent,
        createdAt: session.created_at,
        expiresAt: session.expires_at,
        isCurrent: session.id === req.user?.sessionId,
      })),
    });
  } catch (error) {
    logger.error("Sessions fetch error:", error);
    res.status(500).json({ message: "Server error fetching sessions" });
  }
});

export default router;
