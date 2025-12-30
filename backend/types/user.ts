/** User entity from database */
interface User {
  id: number;
  email: string;
  password: string;
  email_verified: number; // 0 = false, 1 = true (SQLite)
  created_at: string;
}

export { User };
