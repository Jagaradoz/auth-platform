import { Request, Response } from "express";
import bcrypt from "bcryptjs";
import { findUserById, findUserByEmail, createUser } from "../services/user.service";
import {
  createSessionRecord,
  findActiveSessionById,
  findActiveSessionsByUserId,
  deleteSessionById,
  deleteSessionsByUserId,
} from "../services/session.service";
import {
  generateAccessToken,
  findRefreshTokenByHash,
  deleteRefreshTokenById,
  deleteRefreshTokensBySessionId,
  deleteRefreshTokensByUserId,
  hashRefreshToken,
  issueRefreshToken,
  clearRefreshTokenCookie,
} from "../services/token.service";
import {
  createVerificationToken,
  findVerificationTokenByHash,
  hashVerificationToken,
  deleteVerificationTokenById,
  markUserAsVerified,
} from "../services/verification.service";
import { sendVerificationEmail } from "../services/email.service";
import { registerSchema, loginSchema } from "../config/validation";
import logger from "../config/logger";

const SESSION_EXPIRY_DAYS = parseInt(process.env.SESSION_EXPIRY_DAYS!, 10);

// @route   POST /api/auth/register
// @desc    Register a new user with email and password
// @access  Public
const register = async (req: Request, res: Response): Promise<void> => {
  try {
    // Validate inputs
    const validation = registerSchema.safeParse(req.body);
    if (!validation.success) {
      const errorMessage = validation.error.issues[0].message;
      logger.warn(`Registration validation failed: ${errorMessage}`);
      res.status(400).json({ message: errorMessage });
      return;
    }

    const { email, password } = validation.data;

    // Check if user exists
    const existingUser = await findUserByEmail(email);
    if (existingUser) {
      logger.warn(`Registration attempt with existing email: ${email}`);
      res.status(400).json({ message: "User with this email already exists" });
      return;
    }

    // Hash password and create user
    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);
    const userId = await createUser(email, passwordHash);

    // Generate verification token and send email
    const verificationToken = await createVerificationToken(userId);
    const emailSent = await sendVerificationEmail(email, verificationToken);

    logger.info(`New user registered: ${email} (ID: ${userId}), Email sent: ${emailSent}`);
    res.status(201).json({
      message: "User registered successfully. Please check your email to verify your account.",
      userId,
    });
  } catch (error) {
    logger.error("Registration error:", error);
    res.status(500).json({ message: "Server error during registration" });
  }
};

// @route   POST /api/auth/login
// @desc    Authenticate user and return access token with refresh token cookie
// @access  Public
const login = async (req: Request, res: Response): Promise<void> => {
  try {
    // Validate inputs
    const validation = loginSchema.safeParse(req.body);
    if (!validation.success) {
      const errorMessage = validation.error.issues[0].message;
      logger.warn(`Login validation failed: ${errorMessage}`);
      res.status(400).json({ message: errorMessage });
      return;
    }

    const { email, password } = validation.data;

    // Authenticate user
    const user = await findUserByEmail(email);
    if (!user) {
      logger.warn(`Failed login attempt for: ${email}`);
      res.status(401).json({ message: "Invalid credentials" });
      return;
    }

    // Check if password is correct
    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) {
      logger.warn(`Failed login attempt for: ${email}`);
      res.status(401).json({ message: "Invalid credentials" });
      return;
    }

    // Create a new session
    const metadata = {
      device: (req.headers["x-device"] as string) || "Unknown",
      ip: req.ip || req.socket.remoteAddress || "Unknown",
      userAgent: req.headers["user-agent"] || "Unknown",
    };
    const expiresAt = new Date(
      Date.now() + SESSION_EXPIRY_DAYS * 24 * 60 * 60 * 1000,
    ).toISOString();
    const sessionId = await createSessionRecord(
      user.id,
      metadata.device,
      metadata.ip,
      metadata.userAgent,
      expiresAt,
    );

    // Generate access and refresh tokens
    const accessToken = generateAccessToken({
      id: user.id,
      email: user.email,
      sessionId,
    });
    await issueRefreshToken(res, user.id, sessionId);

    logger.info(`User logged in successfully: ${email} (Session: ${sessionId})`);
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
};

// @route   POST /api/auth/logout
// @desc    Logout user - invalidate current session and refresh token
// @access  Private
const logout = async (req: Request, res: Response): Promise<void> => {
  try {
    const sessionId = req.user?.sessionId;

    if (sessionId) {
      // Delete refresh tokens for this session first (due to FK constraint)
      await deleteRefreshTokensBySessionId(sessionId);
      // Delete the session
      await deleteSessionById(sessionId);
    }

    logger.info(`User logged out: ${req.user?.email} (Session: ${sessionId})`);
    clearRefreshTokenCookie(res);
    res.json({
      message: "Logout successful",
    });
  } catch (error) {
    logger.error("Logout error:", error);
    res.status(500).json({ message: "Server error during logout" });
  }
};

// @route   POST /api/auth/logout-all
// @desc    Logout user from all sessions - invalidate all sessions and refresh tokens
// @access  Private
const logoutAll = async (req: Request, res: Response): Promise<void> => {
  try {
    const userId = req.user?.id;

    if (!userId) {
      res.status(401).json({ message: "User not found" });
      return;
    }

    // Delete all refresh tokens for the user first (due to FK constraint)
    await deleteRefreshTokensByUserId(userId);
    // Delete all sessions for the user
    await deleteSessionsByUserId(userId);

    logger.info(`User logged out from all sessions: ${req.user?.email}`);
    clearRefreshTokenCookie(res);
    res.json({
      message: "Logged out from all sessions successfully",
    });
  } catch (error) {
    logger.error("Logout all error:", error);
    res.status(500).json({ message: "Server error during logout" });
  }
};

// @route   GET /api/auth/sessions
// @desc    Get all active sessions for the authenticated user
// @access  Private
const getSessions = async (req: Request, res: Response): Promise<void> => {
  try {
    const userId = req.user?.id;
    if (!userId) {
      res.status(401).json({ message: "User not found" });
      return;
    }

    const sessions = await findActiveSessionsByUserId(userId);

    logger.info(`User ${req.user?.email} fetched ${sessions.length} active sessions`);
    res.json({
      sessions: sessions.map((s) => ({
        id: s.id,
        device: s.device,
        ip: s.ip,
        userAgent: s.user_agent,
        createdAt: s.created_at,
        expiresAt: s.expires_at,
        isCurrent: s.id === req.user?.sessionId,
      })),
    });
  } catch (error) {
    logger.error("Sessions fetch error:", error);
    res.status(500).json({ message: "Server error fetching sessions" });
  }
};

// @route   POST /api/auth/refresh
// @desc    Refresh access token using refresh token cookie
// @access  Public
const refresh = async (req: Request, res: Response): Promise<void> => {
  try {
    const refreshToken = req.cookies?.refreshToken;

    if (!refreshToken) {
      logger.warn("Refresh attempt without token");
      res.status(401).json({ message: "Refresh token not provided" });
      return;
    }

    // Validate refresh token
    const tokenHash = hashRefreshToken(refreshToken);
    const storedToken = await findRefreshTokenByHash(tokenHash);
    if (!storedToken) {
      logger.warn("Invalid refresh token attempted");
      res.status(401).json({ message: "Invalid or expired refresh token" });
      return;
    }

    if (new Date(storedToken.expires_at) < new Date()) {
      await deleteRefreshTokenById(storedToken.id);
      logger.warn("Expired refresh token attempted");
      res.status(401).json({ message: "Invalid or expired refresh token" });
      return;
    }

    const session = await findActiveSessionById(storedToken.session_id);
    if (!session) {
      await deleteRefreshTokenById(storedToken.id);
      logger.warn("Refresh token for expired session attempted");
      res.status(401).json({ message: "Invalid or expired refresh token" });
      return;
    }

    const user = await findUserById(storedToken.user_id);
    if (!user) {
      await deleteRefreshTokenById(storedToken.id);
      logger.warn("Refresh token for non-existent user attempted");
      res.status(401).json({ message: "Invalid or expired refresh token" });
      return;
    }

    // Delete old token and issue new tokens
    await deleteRefreshTokenById(storedToken.id);

    const newAccessToken = generateAccessToken({
      id: user.id,
      email: user.email,
      sessionId: storedToken.session_id,
    });
    await issueRefreshToken(res, user.id, storedToken.session_id);

    logger.info(`Token refreshed for user: ${user.email}`);
    res.json({
      message: "Token refreshed successfully",
      token: newAccessToken,
    });
  } catch (error) {
    logger.error("Token refresh error:", error);
    res.status(500).json({ message: "Server error during token refresh" });
  }
};

// @route   GET /api/auth/verify/:token
// @desc    Verify user email with token
// @access  Public
const verifyEmail = async (req: Request, res: Response): Promise<void> => {
  try {
    const { token } = req.params;

    if (!token) {
      res.status(400).json({ message: "Verification token is required" });
      return;
    }

    // Find token hash in database
    const tokenHash = hashVerificationToken(token);
    const storedToken = await findVerificationTokenByHash(tokenHash);

    if (!storedToken) {
      logger.warn("Invalid verification token attempted");
      res.status(400).json({ message: "Invalid or expired verification token" });
      return;
    }

    // Check if token is expired
    if (new Date(storedToken.expires_at) < new Date()) {
      await deleteVerificationTokenById(storedToken.id);
      logger.warn("Expired verification token attempted");
      res.status(400).json({ message: "Verification token has expired" });
      return;
    }

    // Get user to verify they exist
    const user = await findUserById(storedToken.user_id);
    if (!user) {
      await deleteVerificationTokenById(storedToken.id);
      logger.warn("Verification token for non-existent user");
      res.status(400).json({ message: "User not found" });
      return;
    }

    // Mark user as verified and delete token
    await markUserAsVerified(storedToken.user_id);
    await deleteVerificationTokenById(storedToken.id);

    logger.info(`Email verified for user: ${user.email}`);
    res.json({ message: "Email verified successfully. You can now log in." });
  } catch (error) {
    logger.error("Email verification error:", error);
    res.status(500).json({ message: "Server error during email verification" });
  }
};

export { register, login, logout, logoutAll, getSessions, refresh, verifyEmail };
