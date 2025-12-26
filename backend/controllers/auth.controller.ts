import { Request, Response } from "express";
import * as authService from "../services/auth.service";
import * as tokenService from "../services/token.service";
import * as sessionService from "../services/session.service";
import { deleteRefreshTokenById } from "../models/refreshToken.model";
import { registerSchema, loginSchema } from "../config/validation";
import logger from "../config/logger";

// @route   POST /api/auth/register
const register = async (req: Request, res: Response): Promise<void> => {
  try {
    const validation = registerSchema.safeParse(req.body);
    if (!validation.success) {
      const errorMessage = validation.error.issues[0].message;
      logger.warn(`Registration validation failed: ${errorMessage}`);
      res.status(400).json({ message: errorMessage });
      return;
    }

    const { email, password } = validation.data;
    const { userId } = await authService.registerUser(email, password);

    res.status(201).json({
      message: "User registered successfully",
      userId,
    });
  } catch (error) {
    if (error instanceof Error && error.message === "User with this email already exists") {
      logger.warn(`Registration attempt with existing email: ${req.body.email}`);
      res.status(400).json({ message: error.message });
      return;
    }
    logger.error("Registration error:", error);
    res.status(500).json({ message: "Server error during registration" });
  }
};

// @route   POST /api/auth/login
const login = async (req: Request, res: Response): Promise<void> => {
  try {
    const validation = loginSchema.safeParse(req.body);
    if (!validation.success) {
      const errorMessage = validation.error.issues[0].message;
      logger.warn(`Login validation failed: ${errorMessage}`);
      res.status(400).json({ message: errorMessage });
      return;
    }

    const { email, password } = validation.data;
    const metadata = {
      device: (req.headers["x-device"] as string) || "Unknown",
      ip: req.ip || req.socket.remoteAddress || "Unknown",
      userAgent: req.headers["user-agent"] || "Unknown",
    };

    const { user, sessionId } = await authService.authenticateUser(email, password, metadata);

    const accessToken = tokenService.generateAccessToken({
      id: user.id,
      email: user.email,
      sessionId,
    });

    await tokenService.issueRefreshToken(res, user.id, sessionId);

    res.json({
      message: "Logged in successfully",
      token: accessToken,
      user: {
        id: user.id,
        email: user.email,
      },
    });
  } catch (error) {
    if (error instanceof Error && error.message === "Invalid credentials") {
      logger.warn(`Failed login attempt for: ${req.body.email}`);
      res.status(401).json({ message: error.message });
      return;
    }
    logger.error("Login error:", error);
    res.status(500).json({ message: "Server error during login" });
  }
};

// @route   POST /api/auth/logout
const logout = async (req: Request, res: Response): Promise<void> => {
  try {
    logger.info(`User logged out: ${req.user?.email}`);
    tokenService.clearRefreshTokenCookie(res);
    res.json({
      message: "Logout successful",
      user: req.user,
    });
  } catch (error) {
    logger.error("Logout error:", error);
    res.status(500).json({ message: "Server error during logout" });
  }
};

// @route   GET /api/auth/sessions
const getSessions = async (req: Request, res: Response): Promise<void> => {
  try {
    const userId = req.user?.id;
    if (!userId) {
      res.status(401).json({ message: "User not found" });
      return;
    }

    const sessions = await sessionService.getActiveSessions(userId);

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
const refresh = async (req: Request, res: Response): Promise<void> => {
  try {
    const refreshToken = req.cookies?.refreshToken;

    if (!refreshToken) {
      logger.warn("Refresh attempt without token");
      res.status(401).json({ message: "Refresh token not provided" });
      return;
    }

    const result = await authService.validateRefreshToken(refreshToken);
    if (!result) {
      res.status(401).json({ message: "Invalid or expired refresh token" });
      return;
    }

    const { user, sessionId, storedTokenId } = result;

    await deleteRefreshTokenById(storedTokenId);

    const newAccessToken = tokenService.generateAccessToken({
      id: user.id,
      email: user.email,
      sessionId,
    });

    await tokenService.issueRefreshToken(res, user.id, sessionId);

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

export { register, login, logout, getSessions, refresh };
