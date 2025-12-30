/** Session entity from database */
interface Session {
  id: number;
  user_id: number;
  device: string | null;
  ip: string | null;
  user_agent: string | null;
  created_at: string;
  expires_at: string;
}

export { Session };
