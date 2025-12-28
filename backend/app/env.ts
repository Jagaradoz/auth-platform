import "dotenv/config";

import { z } from "zod";

const envSchema = z.object({
  // Server
  PORT: z.string(),
  NODE_ENV: z.enum(["development", "production", "test"]),
  FRONTEND_URL: z.string().url(),

  // Logging
  LOG_LEVEL: z.enum(["error", "warn", "info", "debug"]),

  // Tokens & Sessions
  JWT_SECRET: z.string().min(32, "must be at least 32 characters"),
  ACCESS_TOKEN_EXPIRY_TIME: z.string(),
  REFRESH_TOKEN_EXPIRY_DAYS: z.string(),
  SESSION_EXPIRY_DAYS: z.string(),

  // Email Service
  SMTP_HOST: z.string(),
  SMTP_PORT: z.string(),
  SMTP_USER: z.string(),
  SMTP_PASS: z.string(),
  SMTP_FROM: z.string(),
  VERIFICATION_TOKEN_EXPIRY_HOURS: z.string(),
});

const allVars = [
  "JWT_SECRET",
  "PORT",
  "NODE_ENV",
  "FRONTEND_URL",
  "LOG_LEVEL",
  "ACCESS_TOKEN_EXPIRY_TIME",
  "REFRESH_TOKEN_EXPIRY_DAYS",
  "SESSION_EXPIRY_DAYS",
  "SMTP_HOST",
  "SMTP_PORT",
  "SMTP_USER",
  "SMTP_PASS",
  "SMTP_FROM",
  "VERIFICATION_TOKEN_EXPIRY_HOURS",
];

const colors = {
  green: "\x1b[32m",
  red: "\x1b[31m",
  yellow: "\x1b[33m",
  reset: "\x1b[0m",
};

/** Validate environment variables */
const validateEnv = (): void => {
  console.log("Checking environment variables...\n");

  const result = envSchema.safeParse(process.env);
  const errors = new Map<string, string>();

  // Collect errors by key
  if (!result.success) {
    result.error.issues.forEach((issue) => {
      const key = issue.path[0] as string;
      errors.set(key, issue.message);
    });
  }

  let hasError = false;

  // Log all variables
  allVars.forEach((key) => {
    const value = process.env[key];
    const error = errors.get(key);

    if (error) {
      console.log(`${colors.red}[INVALID]${colors.reset} ${key} - ${error}`);
      hasError = true;
    } else if (value) {
      console.log(`${colors.green}[VALID]${colors.reset} ${key}`);
    } else {
      console.log(`${colors.red}[INVALID]${colors.reset} ${key} - not set`);
      hasError = true;
    }
  });

  console.log("");

  if (hasError) {
    console.log(`${colors.red}Environment check failed.${colors.reset}\n`);
    process.exit(1);
  } else {
    console.log(`${colors.green}Environment check passed.${colors.reset}\n`);
  }
};

validateEnv();
