import { dbRun, dbGet } from "../config/db";
import { User } from "../types";

/** Find user by ID */
const findUserById = async (id: number): Promise<User | undefined> => {
  return await dbGet<User>("SELECT * FROM users WHERE id = ?", [id]);
};

/** Find user by email */
const findUserByEmail = async (email: string): Promise<User | undefined> => {
  return await dbGet<User>("SELECT * FROM users WHERE email = ?", [email]);
};

/** Create a new user and return the user ID */
const createUser = async (email: string, passwordHash: string): Promise<number> => {
  const result = await dbRun("INSERT INTO users (email, password_hash) VALUES (?, ?)", [
    email,
    passwordHash,
  ]);
  return result.lastID;
};

export { findUserById, findUserByEmail, createUser };
