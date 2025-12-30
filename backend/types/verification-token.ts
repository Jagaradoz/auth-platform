/** Verification token entity from database */
interface VerificationToken {
  id: number;
  user_id: number;
  token: string;
  expires_at: string;
  created_at: string;
}

export { VerificationToken };
