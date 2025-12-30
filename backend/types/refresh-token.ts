/** Refresh token entity from database */
interface RefreshToken {
  id: number;
  user_id: number;
  token: string;
  session_id: number;
  expires_at: string;
  created_at: string;
}

export { RefreshToken };
