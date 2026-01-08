import { Router } from "express";
import * as authController from "../controllers/auth.controller";
import { authenticateAccessToken } from "../middlewares/auth.middleware";
import { loginLimiter, registerLimiter } from "../middlewares/rate-limiter.middleware";

const router = Router();

router.post("/register", registerLimiter, authController.register);
router.post("/login", loginLimiter, authController.login);
router.post("/logout", authenticateAccessToken, authController.logout);
router.post("/logout-all", authenticateAccessToken, authController.logoutAll);
router.get("/sessions", authenticateAccessToken, authController.getSessions);
router.post("/refresh", authController.refresh);
router.get("/verify/:token", authController.verifyEmail);
router.post("/forgot-password", authController.forgotPassword);
router.post("/reset-password", authController.resetPassword);
router.post("/resend-verification", authController.resendVerification);

export default router;
