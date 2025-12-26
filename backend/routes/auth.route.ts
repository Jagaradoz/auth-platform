import { Router, Request, Response } from "express";
import bcrypt from "bcryptjs";
import { dbRun, dbGet, dbAll } from "../utils/db";
import {
  authenticateToken,
  generateToken,
  generateRefreshToken,
  hashToken,
  REFRESH_TOKEN_EXPIRY_DAYS,
} from "../middleware/auth.middleware";
import { loginLimiter, registerLimiter } from "../middleware/rateLimiter.middleware";
import { registerSchema, loginSchema } from "../utils/validation";
import { User, Session, RefreshToken } from "../types";
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

    // Generate access token with session ID
    const accessToken = generateToken({
      id: user.id,
      email: user.email,
      sessionId: sessionResult.lastID,
    });

    // Generate and store refresh token
    const refreshToken = generateRefreshToken();
    const refreshTokenHash = hashToken(refreshToken);
    const refreshExpiresAt = new Date(
      Date.now() + REFRESH_TOKEN_EXPIRY_DAYS * 24 * 60 * 60 * 1000,
    ).toISOString();

    await dbRun(
      "INSERT INTO refresh_tokens (user_id, token_hash, session_id, expires_at) VALUES (?, ?, ?, ?)",
      [user.id, refreshTokenHash, sessionResult.lastID, refreshExpiresAt],
    );

    // Set refresh token as httpOnly cookie
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: REFRESH_TOKEN_EXPIRY_DAYS * 24 * 60 * 60 * 1000,
    });

    logger.info(`User logged in successfully: ${email} (Session: ${sessionResult.lastID})`);
    res.json({
      message: "Logged in successfully",
      token: accessToken,
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

// @router  POST /api/auth/refresh
// @desc    Exchange refresh token for new access token (with token rotation)
// @access  Public (requires valid refresh token cookie)
router.post("/refresh", async (req: Request, res: Response): Promise<void> => {
  try {
    const refreshToken = req.cookies?.refreshToken;

    if (!refreshToken) {
      logger.warn("Refresh attempt without token");
      res.status(401).json({ message: "Refresh token not provided" });
      return;
    }

    // Hash the incoming token to compare with stored hash
    const tokenHash = hashToken(refreshToken);

    // Find the refresh token in database
    const storedToken = await dbGet<RefreshToken>(
      "SELECT * FROM refresh_tokens WHERE token_hash = ?",
      [tokenHash],
    );

    if (!storedToken) {
      logger.warn("Invalid refresh token attempted");
      res.status(401).json({ message: "Invalid refresh token" });
      return;
    }

    // Check if token is expired, then delete it
    if (new Date(storedToken.expires_at) < new Date()) {
      await dbRun("DELETE FROM refresh_tokens WHERE id = ?", [storedToken.id]);
      logger.warn("Expired refresh token attempted");
      res.status(401).json({ message: "Refresh token expired" });
      return;
    }

    // Verify the session is still active
    const session = await dbGet<Session>(
      "SELECT * FROM sessions WHERE id = ? AND expires_at > datetime('now')",
      [storedToken.session_id],
    );

    if (!session) {
      // Session expired or invalidated, delete the refresh token
      await dbRun("DELETE FROM refresh_tokens WHERE id = ?", [storedToken.id]);
      logger.warn("Refresh token for expired session attempted");
      res.status(401).json({ message: "Session expired" });
      return;
    }

    // Get user info
    const user = await dbGet<User>("SELECT * FROM users WHERE id = ?", [storedToken.user_id]);
    if (!user) {
      await dbRun("DELETE FROM refresh_tokens WHERE id = ?", [storedToken.id]);
      logger.warn("Refresh token for non-existent user attempted");
      res.status(401).json({ message: "User not found" });
      return;
    }

    // Token rotation: Delete old refresh token
    await dbRun("DELETE FROM refresh_tokens WHERE id = ?", [storedToken.id]);

    // Generate new access token
    const newAccessToken = generateToken({
      id: user.id,
      email: user.email,
      sessionId: storedToken.session_id,
    });

    // Generate new refresh token (rotation)
    const newRefreshToken = generateRefreshToken();
    const newRefreshTokenHash = hashToken(newRefreshToken);
    const newRefreshExpiresAt = new Date(
      Date.now() + REFRESH_TOKEN_EXPIRY_DAYS * 24 * 60 * 60 * 1000,
    ).toISOString();

    await dbRun(
      "INSERT INTO refresh_tokens (user_id, token_hash, session_id, expires_at) VALUES (?, ?, ?, ?)",
      [user.id, newRefreshTokenHash, storedToken.session_id, newRefreshExpiresAt],
    );

    // Set new refresh token cookie
    res.cookie("refreshToken", newRefreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: REFRESH_TOKEN_EXPIRY_DAYS * 24 * 60 * 60 * 1000,
    });

    logger.info(`Token refreshed for user: ${user.email}`);
    res.json({
      message: "Token refreshed successfully",
      token: newAccessToken,
    });
  } catch (error) {
    logger.error("Token refresh error:", error);
    res.status(500).json({ message: "Server error during token refresh" });
  }
});

export default router;
