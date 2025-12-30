# Auth System

A full-stack authentication system implementing secure JWT-based authentication, including login, registration, and token refresh. It provides robust session management with the ability to view active sessions, log out individual devices, or revoke access across all devices. The system also includes email verification to ensure account integrity and security.

### Backend Techs

- Node JS
- Express JS
- SQLite3
- JSON Web Tokens (JWT) & access/refresh token logic
- Helmet
- CORS
- Bcryptjs
- Express-rate-limit
- Zod
- Nodemailer
- Winston

### Frontend Techs

- React JS (Vite)
- React Router
- Zustand
- Axios
- Bootstrap 5, Bootstrap Icons, Lucide React

---

## Backend

### API Routes

All authentication routes are prefixed with `/api/auth`.

| Method | Endpoint                  | Description                                     | Auth Required |
| ------ | ------------------------- | ----------------------------------------------- | ------------- |
| `POST` | `/api/auth/register`      | Register a new user account                     | No            |
| `POST` | `/api/auth/login`         | Login with email and password                   | No            |
| `POST` | `/api/auth/logout`        | Logout current session                          | Yes           |
| `POST` | `/api/auth/logout-all`    | Logout from all sessions                        | Yes           |
| `GET`  | `/api/auth/sessions`      | Get all active sessions                         | Yes           |
| `POST` | `/api/auth/refresh`       | Refresh access token using refresh token cookie | No            |
| `GET`  | `/api/auth/verify/:token` | Verify email address                            | No            |

### Middleware

- **Rate Limiting:** Login and registration endpoints are rate-limited to prevent brute force attacks
- **Authentication:** Access token validation middleware for protected routes

---

## Frontend

_Implementing, Documentation coming soon..._
