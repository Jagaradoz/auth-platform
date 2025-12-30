# Auth System

A production-ready full-stack authentication system built with modern security practices. It implements secure JWT-based authentication with access and refresh token rotation, comprehensive session management across multiple devices, and complete email-based account verification and password recovery flows.

**Main Features:**

- Registration and login system
- JWT access tokens and refresh tokens
- Multi-session tracking and management
- Email verification with secure token-based flow
- Password reset system via email
- Rate limiting on authentication endpoints

---

## Backend

### Technologies

`Node JS`
`Express JS`
`SQLite3`
`JSON Web Tokens`
`Helmet`
`CORS`
`Bcryptjs`
`Express-rate-limit`
`Zod`
`Nodemailer`
`Winston`

### Middleware

- **Rate Limiting:** Login and registration endpoints are rate-limited to prevent brute force attacks
- **Authentication:** Access token validation middleware for protected routes

### API Routes

All authentication routes are prefixed with `/api/auth`.

| Method | Endpoint                        | Description                                     | Auth Required |
| ------ | ------------------------------- | ----------------------------------------------- | ------------- |
| `POST` | `/api/auth/register`            | Register a new user account                     | No            |
| `POST` | `/api/auth/login`               | Login with email and password                   | No            |
| `POST` | `/api/auth/logout`              | Logout current session                          | Yes           |
| `POST` | `/api/auth/logout-all`          | Logout from all sessions                        | Yes           |
| `GET`  | `/api/auth/sessions`            | Get all active sessions                         | Yes           |
| `POST` | `/api/auth/refresh`             | Refresh access token using refresh token cookie | No            |
| `GET`  | `/api/auth/verify/:token`       | Verify email address                            | No            |
| `POST` | `/api/auth/forgot-password`     | Request password reset email                    | No            |
| `POST` | `/api/auth/reset-password`      | Reset password with token                       | No            |
| `POST` | `/api/auth/resend-verification` | Resend verification email                       | No            |

---

## Frontend

### Technologies

`React JS (Vite)`
`React Router`
`Zustand`
`Axios`
`Zod`
`Bootstrap 5`
`Bootstrap Icons`
`Lucide React`

### Features

- **Protected Routes:** Dashboard requires authentication via `ProtectedRoute` component
- **Auto Token Refresh:** Axios interceptor automatically refreshes expired tokens
- **Session Management:** View all active sessions with device info, logout individual or all sessions
- **Form Validation:** Real-time validation using Zod schemas

### Pages

| Route              | Description                          | Protected |
| ------------------ | ------------------------------------ | --------- |
| `/`                | Home page                            | No        |
| `/login`           | Login form with forgot password link | No        |
| `/register`        | Registration form with validation    | No        |
| `/check-email`     | Post-registration email instructions | No        |
| `/verify`          | Email verification handler           | No        |
| `/forgot-password` | Request password reset email         | No        |
| `/reset-password`  | Set new password with token          | No        |
| `/dashboard`       | User dashboard with active sessions  | Yes       |
