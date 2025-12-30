import { Request, Response } from "express";
import bcrypt from "bcryptjs";
import * as userService from "../services/user.service";
import * as sessionService from "../services/session.service";
import * as tokenService from "../services/token.service";
import * as verificationService from "../services/verification.service";
import * as passwordResetService from "../services/password-reset.service";
import * as emailService from "../services/email.service";
import { registerSchema, loginSchema } from "../config/validation";
import logger from "../config/logger";

const SESSION_EXPIRY_DAYS = parseInt(process.env.SESSION_EXPIRY_DAYS!, 10);
const MS_PER_DAY = 24 * 60 * 60 * 1000;

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
    const existingUser = await userService.findUserByEmail(email);
    if (existingUser) {
      logger.warn(`Registration attempt with existing email: ${email}`);
      res.status(400).json({ message: "User with this email already exists" });
      return;
    }

    // Hash password and create user
    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);
    const userId = await userService.createUser(email, passwordHash);

    // Generate verification token and send email
    const plainToken = await verificationService.createVerificationToken(userId);
    const emailSent = await emailService.sendVerificationEmail(email, plainToken);

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
    const user = await userService.findUserByEmail(email);
    if (!user) {
      logger.warn(`Failed login attempt for: ${email}`);
      res.status(401).json({ message: "Invalid credentials" });
      return;
    }

    // Check if password is correct
    const isMatch = await bcrypt.compare(password, user.password);
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
    const expiresAt = new Date(Date.now() + SESSION_EXPIRY_DAYS * MS_PER_DAY).toISOString();
    const sessionId = await sessionService.createSession(
      user.id,
      metadata.device,
      metadata.ip,
      metadata.userAgent,
      expiresAt,
    );

    // Generate access and refresh tokens
    const accessToken = tokenService.generateAccessToken({
      id: user.id,
      email: user.email,
      sessionId,
    });
    await tokenService.createRefreshToken(res, user.id, sessionId);

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
    // Check if user is authenticated
    const userId = req.user?.id;
    if (!userId) {
      res.status(401).json({ message: "User not found" });
      return;
    }

    const sessionId = req.user?.sessionId;
    if (sessionId) {
      // Delete refresh tokens and session respectively
      await tokenService.deleteRefreshTokensBySessionId(sessionId);
      await sessionService.deleteSessionById(sessionId);
    }

    logger.info(`User logged out: ${req.user?.email} (Session: ${sessionId})`);
    tokenService.clearRefreshTokenCookie(res);
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
    // Check if user is authenticated
    const userId = req.user?.id;
    if (!userId) {
      res.status(401).json({ message: "User not found" });
      return;
    }

    // Delete refresh tokens and session respectively
    await tokenService.deleteRefreshTokensByUserId(userId);
    await sessionService.deleteSessionsByUserId(userId);

    logger.info(`User logged out from all sessions: ${req.user?.email}`);
    tokenService.clearRefreshTokenCookie(res);
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
    // Check if user is authenticated
    const userId = req.user?.id;
    if (!userId) {
      res.status(401).json({ message: "User not found" });
      return;
    }

    const sessions = await sessionService.findActiveSessionsByUserId(userId);

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
    // Check if refresh token is provided
    const refreshToken = req.cookies?.refreshToken;
    if (!refreshToken) {
      logger.warn("Refresh attempt without token");
      res.status(401).json({ message: "Refresh token not provided" });
      return;
    }

    // Check if refresh token exists
    const hashedToken = tokenService.hashRefreshToken(refreshToken);
    const storedToken = await tokenService.findRefreshTokenByHash(hashedToken);
    if (!storedToken) {
      logger.warn("Invalid refresh token attempted");
      res.status(401).json({ message: "Invalid or expired refresh token" });
      return;
    }

    // Check if refresh token is expired
    if (new Date(storedToken.expires_at) < new Date()) {
      await tokenService.deleteRefreshTokenById(storedToken.id);
      logger.warn("Expired refresh token attempted");
      res.status(401).json({ message: "Invalid or expired refresh token" });
      return;
    }

    // Check if session exists
    const session = await sessionService.findActiveSessionById(storedToken.session_id);
    if (!session) {
      await tokenService.deleteRefreshTokenById(storedToken.id);
      logger.warn("Refresh token for expired session attempted");
      res.status(401).json({ message: "Invalid or expired refresh token" });
      return;
    }

    // Check if user exists
    const user = await userService.findUserById(storedToken.user_id);
    if (!user) {
      await tokenService.deleteRefreshTokenById(storedToken.id);
      logger.warn("Refresh token for non-existent user attempted");
      res.status(401).json({ message: "Invalid or expired refresh token" });
      return;
    }

    // Delete old token and issue new tokens
    await tokenService.deleteRefreshTokenById(storedToken.id);

    const newAccessToken = tokenService.generateAccessToken({
      id: user.id,
      email: user.email,
      sessionId: storedToken.session_id,
    });
    await tokenService.createRefreshToken(res, user.id, storedToken.session_id);

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
    // Check if token is provided
    const { token } = req.params;
    if (!token) {
      res.status(400).json({ message: "Verification token is required" });
      return;
    }

    // Check if token exists
    const hashedToken = verificationService.hashVerificationToken(token);
    const storedToken = await verificationService.findVerificationTokenByHash(hashedToken);
    if (!storedToken) {
      logger.warn("Invalid verification token attempted");
      res.status(400).json({ message: "Invalid or expired verification token" });
      return;
    }

    // Check if token is expired
    if (new Date(storedToken.expires_at) < new Date()) {
      await verificationService.deleteVerificationTokenById(storedToken.id);
      logger.warn("Expired verification token attempted");
      res.status(400).json({ message: "Verification token has expired" });
      return;
    }

    // Check if user exists
    const user = await userService.findUserById(storedToken.user_id);
    if (!user) {
      await verificationService.deleteVerificationTokenById(storedToken.id);
      logger.warn("Verification token for non-existent user");
      res.status(400).json({ message: "User not found" });
      return;
    }

    // Mark user as verified and delete token
    await verificationService.markUserAsVerified(storedToken.user_id);
    await verificationService.deleteVerificationTokenById(storedToken.id);

    logger.info(`Email verified for user: ${user.email}`);
    res.json({ message: "Email verified successfully. You can now log in." });
  } catch (error) {
    logger.error("Email verification error:", error);
    res.status(500).json({ message: "Server error during email verification" });
  }
};

// @route   POST /api/auth/forgot-password
// @desc    Request password reset email
// @access  Public
const forgotPassword = async (req: Request, res: Response): Promise<void> => {
  try {
    // Check if email is provided
    const { email } = req.body;
    if (!email) {
      res.status(400).json({ message: "Email is required" });
      return;
    }

    // Check if user exists
    const user = await userService.findUserByEmail(email);
    if (user) {
      const token = await passwordResetService.createPasswordResetToken(user.id);
      await emailService.sendPasswordResetEmail(email, token);
      logger.info(`Password reset email sent to: ${email}`);
    }

    res.json({
      message: "Password reset link has been sent, Please check your email.",
    });
  } catch (error) {
    logger.error("Forgot password error:", error);
    res.status(500).json({ message: "Server error during password reset request" });
  }
};

// @route   POST /api/auth/reset-password
// @desc    Reset password using token
// @access  Public
const resetPassword = async (req: Request, res: Response): Promise<void> => {
  try {
    // Check if token and password are provided
    const { token, password } = req.body;
    if (!token || !password) {
      res.status(400).json({ message: "Token and password are required" });
      return;
    }

    // Validate password length
    if (password.length < 6) {
      res.status(400).json({ message: "Password must be at least 6 characters" });
      return;
    }

    // Check if token exists
    const hashedToken = passwordResetService.hashResetToken(token);
    const storedToken = await passwordResetService.findPasswordResetTokenByHash(hashedToken);
    if (!storedToken) {
      logger.warn("Invalid password reset token attempted");
      res.status(400).json({ message: "Invalid or expired reset token" });
      return;
    }

    // Check if token is expired
    if (new Date(storedToken.expires_at) < new Date()) {
      await passwordResetService.deletePasswordResetTokenById(storedToken.id);
      logger.warn("Expired password reset token attempted");
      res.status(400).json({ message: "Reset token has expired" });
      return;
    }

    // Hash new password and update user
    const passwordHash = await bcrypt.hash(password, 10);
    await userService.updateUserPassword(storedToken.user_id, passwordHash);
    await passwordResetService.deletePasswordResetTokenById(storedToken.id);

    // Invalidate all sessions for security
    await tokenService.deleteRefreshTokensByUserId(storedToken.user_id);
    await sessionService.deleteSessionsByUserId(storedToken.user_id);

    logger.info(`Password reset successful for user ID: ${storedToken.user_id}`);
    res.json({
      message: "Password reset successfully. You can now log in with your new password.",
    });
  } catch (error) {
    logger.error("Reset password error:", error);
    res.status(500).json({ message: "Server error during password reset" });
  }
};

// @route   POST /api/auth/resend-verification
// @desc    Resend verification email
// @access  Public
const resendVerification = async (req: Request, res: Response): Promise<void> => {
  try {
    // Check if email is provided
    const { email } = req.body;
    if (!email) {
      res.status(400).json({ message: "Email is required" });
      return;
    }

    // Check if user exists
    const user = await userService.findUserByEmail(email);
    if (!user) {
      res.json({
        message: "If an account with that email exists, a verification email has been sent.",
      });
      return;
    }

    // Check if already verified
    if (user.email_verified === 1) {
      res.status(400).json({ message: "Email is already verified" });
      return;
    }

    // Create new verification token and send email
    const token = await verificationService.createVerificationToken(user.id);
    await emailService.sendVerificationEmail(email, token);

    logger.info(`Verification email resent to: ${email}`);
    res.json({
      message: "If an account with that email exists, a verification email has been sent.",
    });
  } catch (error) {
    logger.error("Resend verification error:", error);
    res.status(500).json({ message: "Server error during resend verification" });
  }
};

export {
  register,
  login,
  logout,
  logoutAll,
  getSessions,
  refresh,
  verifyEmail,
  forgotPassword,
  resetPassword,
  resendVerification,
};
