import nodemailer from "nodemailer";
import logger from "./logger";

// Email configuration - uses Mailtrap for development
// For production, replace with your actual SMTP settings (SendGrid, AWS SES, etc.)
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || "sandbox.smtp.mailtrap.io",
  port: parseInt(process.env.SMTP_PORT || "2525", 10),
  auth: {
    user: process.env.SMTP_USER || "",
    pass: process.env.SMTP_PASS || "",
  },
});

// Verify connection on startup
transporter.verify((error) => {
  if (error) {
    logger.warn("Email transporter not configured:", error.message);
  } else {
    logger.info("Email transporter ready");
  }
});

export default transporter;
