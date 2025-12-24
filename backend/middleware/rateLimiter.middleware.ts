import rateLimit from "express-rate-limit";

/** Rate limiter for login: 50 attempts per 15 minutes */
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50,
  message: { message: "Too many login attempts. Please try again later." },
  standardHeaders: true,
  legacyHeaders: false,
});

/** Rate limiter for register: 50 accounts per hour */
const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 50,
  message: { message: "Too many accounts created. Please try again later." },
  standardHeaders: true,
  legacyHeaders: false,
});

/** Test limiter: 3 requests per 30 seconds */
const testLimiter = rateLimit({
  windowMs: 30 * 1000,
  max: 3,
  message: { message: "Rate limit hit! Wait 30 seconds." },
  standardHeaders: true,
  legacyHeaders: false,
});

export { loginLimiter, registerLimiter, testLimiter };
