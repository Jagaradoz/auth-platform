import transporter from "../config/email";
import logger from "../config/logger";

const FRONTEND_URL = process.env.FRONTEND_URL!;

/** Send verification email to user */
const sendVerificationEmail = async (email: string, token: string): Promise<boolean> => {
  const verificationUrl = `${FRONTEND_URL}/verify?token=${token}`;

  try {
    await transporter.sendMail({
      from: process.env.SMTP_FROM,
      to: email,
      subject: "Verify your email - Auth System",
      html: `
        <!DOCTYPE html>
        <html>
        <head>
          <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 30px; text-align: left; }
            .header { text-align: center; margin-bottom: 30px; padding-bottom: 20px; border-bottom: 1px solid #eee; }
            .brand-name { font-size: 24px; font-weight: 700; color: #1a1a2e; }
            h2 { text-align: left; color: #1a1a2e; }
            p { text-align: left; color: #555; }
            .button-container { text-align: center; margin: 25px 0; }
            .button { display: inline-block; padding: 14px 28px; background: linear-gradient(135deg, #4F46E5 0%, #7C3AED 100%); color: #ffffff !important; text-decoration: none; border-radius: 8px; font-weight: 600; font-size: 15px; }
            .footer { margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee; font-size: 12px; color: #999; text-align: center; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <span class="brand-name">Auth System</span>
            </div>
            <h2>Verify your email address</h2>
            <p>Thanks for registering! Please click the button below to verify your email address:</p>
            <div class="button-container">
              <a href="${verificationUrl}" class="button">Verify Email</a>
            </div>
            <p>This link will expire in 24 hours.</p>
            <div class="footer">
              <p>If you didn't create an account, please ignore this email.</p>
            </div>
          </div>
        </body>
        </html>
      `,
      text: `
        Auth System - Verify your email address
        
        Thanks for registering! Please click the link below to verify your email:
        ${verificationUrl}
        
        This link will expire in 24 hours.
        
        If you didn't create an account, please ignore this email.
      `,
    });

    logger.info(`Verification email sent to: ${email}`);
    return true;
  } catch (error) {
    logger.error(`Failed to send verification email to ${email}:`, error);
    return false;
  }
};

/** Send password reset email to user */
const sendPasswordResetEmail = async (email: string, token: string): Promise<boolean> => {
  const resetUrl = `${FRONTEND_URL}/reset-password?token=${token}`;

  try {
    await transporter.sendMail({
      from: process.env.SMTP_FROM,
      to: email,
      subject: "Reset your password - Auth System",
      html: `
        <!DOCTYPE html>
        <html>
        <head>
          <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 30px; text-align: left; }
            .header { text-align: center; margin-bottom: 30px; padding-bottom: 20px; border-bottom: 1px solid #eee; }
            .brand-name { font-size: 24px; font-weight: 700; color: #1a1a2e; }
            h2 { text-align: left; color: #1a1a2e; }
            p { text-align: left; color: #555; }
            .button-container { text-align: center; margin: 25px 0; }
            .button { display: inline-block; padding: 14px 28px; background: linear-gradient(135deg, #4F46E5 0%, #7C3AED 100%); color: #ffffff !important; text-decoration: none; border-radius: 8px; font-weight: 600; font-size: 15px; }
            .footer { margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee; font-size: 12px; color: #999; text-align: center; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <span class="brand-name">Auth System</span>
            </div>
            <h2>Reset your password</h2>
            <p>You requested to reset your password. Click the button below to set a new password:</p>
            <div class="button-container">
              <a href="${resetUrl}" class="button">Reset Password</a>
            </div>
            <p>This link will expire in 1 hour.</p>
            <div class="footer">
              <p>If you didn't request a password reset, please ignore this email.</p>
            </div>
          </div>
        </body>
        </html>
      `,
      text: `
        Auth System - Reset your password
        
        You requested to reset your password. Click the link below to set a new password:
        ${resetUrl}
        
        This link will expire in 1 hour.
        
        If you didn't request a password reset, please ignore this email.
      `,
    });

    logger.info(`Password reset email sent to: ${email}`);
    return true;
  } catch (error) {
    logger.error(`Failed to send password reset email to ${email}:`, error);
    return false;
  }
};

export { sendVerificationEmail, sendPasswordResetEmail };
