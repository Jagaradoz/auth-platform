/** Password reset token entity from database */
interface PasswordResetToken {
  id: number;
  user_id: number;
  token: string;
  expires_at: string;
  created_at: string;
}

export { PasswordResetToken };
