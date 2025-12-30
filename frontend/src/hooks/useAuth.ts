// Packages
import { create } from "zustand";
import axios from "axios";

// Types
import type { AuthState } from "../types/auth";

// Constants
const BACKEND_URL = import.meta.env.VITE_BACKEND_URL!;

// Functions
const decodeJwtPayload = (token: string): { id: number; email: string } | null => {
  try {
    const payload = token.split(".")[1];
    const decoded = JSON.parse(atob(payload));
    return { id: decoded.id, email: decoded.email };
  } catch {
    return null;
  }
};

// Hook
const useAuth = create<AuthState>((set, get) => ({
  user: null,
  accessToken: null,
  isLoading: true,
  isAuthenticated: false,
  sessions: [],

  register: async (email: string, password: string) => {
    await axios.post(`${BACKEND_URL}/api/auth/register`, { email, password });
  },

  login: async (email: string, password: string) => {
    const response = await axios.post(
      `${BACKEND_URL}/api/auth/login`,
      { email, password },
      { withCredentials: true },
    );

    const token = response.data.token;
    const user = decodeJwtPayload(token);

    set({
      user,
      accessToken: token,
      isAuthenticated: true,
    });
  },

  logout: async () => {
    const { accessToken } = get();

    try {
      await axios.post(
        `${BACKEND_URL}/api/auth/logout`,
        {},
        {
          headers: { Authorization: `Bearer ${accessToken}` },
          withCredentials: true,
        },
      );
    } finally {
      set({ user: null, accessToken: null, isAuthenticated: false, sessions: [] });
    }
  },

  logoutAll: async () => {
    const { accessToken } = get();

    try {
      await axios.post(
        `${BACKEND_URL}/api/auth/logout-all`,
        {},
        {
          headers: { Authorization: `Bearer ${accessToken}` },
          withCredentials: true,
        },
      );
    } finally {
      set({ user: null, accessToken: null, isAuthenticated: false, sessions: [] });
    }
  },

  getSessions: async () => {
    const { accessToken } = get();

    const response = await axios.get(`${BACKEND_URL}/api/auth/sessions`, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    set({ sessions: response.data.sessions });
  },

  refresh: async () => {
    try {
      const response = await axios.post(
        `${BACKEND_URL}/api/auth/refresh`,
        {},
        { withCredentials: true },
      );

      const token = response.data.token;
      const user = decodeJwtPayload(token);

      set({
        user,
        accessToken: token,
        isAuthenticated: true,
      });

      return true;
    } catch {
      set({ user: null, accessToken: null, isAuthenticated: false, sessions: [] });
      return false;
    }
  },

  verifyEmail: async (token: string) => {
    await axios.get(`${BACKEND_URL}/api/auth/verify/${token}`);
  },

  forgotPassword: async (email: string) => {
    await axios.post(`${BACKEND_URL}/api/auth/forgot-password`, { email });
  },

  resetPassword: async (token: string, password: string) => {
    await axios.post(`${BACKEND_URL}/api/auth/reset-password`, { token, password });
  },

  resendVerification: async (email: string) => {
    await axios.post(`${BACKEND_URL}/api/auth/resend-verification`, { email });
  },

  checkAuth: async () => {
    set({ isLoading: true });
    await get().refresh();
    set({ isLoading: false });
  },
}));

// Interceptor
axios.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;
    const errorCode = error.response?.data?.code;

    const isTokenError = errorCode === "TOKEN_EXPIRED" || errorCode === "TOKEN_INVALID";

    if (error.response?.status === 401 && isTokenError && !originalRequest._retry) {
      originalRequest._retry = true;

      const success = await useAuth.getState().refresh();

      if (success) {
        const newToken = useAuth.getState().accessToken;
        originalRequest.headers.Authorization = `Bearer ${newToken}`;
        return axios(originalRequest);
      }
    }

    return Promise.reject(error);
  },
);

export default useAuth;
