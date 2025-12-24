import { z } from "zod";

/** Schema for user registration */
const registerSchema = z.object({
  email: z
    .email()
    .min(1, "Email is required")
    .transform((email) => email.toLowerCase().trim()),
  password: z
    .string()
    .min(6, "Password must be at least 6 characters")
    .regex(/[0-9]/, "Password must contain at least one number"),
});

/** Schema for user login */
const loginSchema = z.object({
  email: z
    .email()
    .min(1, "Email is required")
    .transform((email) => email.toLowerCase().trim()),
  password: z.string().min(1, "Password is required"),
});

// Exports
export type RegisterInput = z.infer<typeof registerSchema>;
export type LoginInput = z.infer<typeof loginSchema>;
export { registerSchema, loginSchema };
