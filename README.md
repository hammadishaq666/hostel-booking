# Hostel Booking API

NestJS backend with PostgreSQL (TypeORM), JWT auth, and email OTP verification.

## Setup

1. Copy `.env.example` to `.env` and set:
   - `DATABASE_URL` – PostgreSQL connection string (e.g. Supabase pooler URI)
   - `JWT_ACCESS_SECRET`, `JWT_REFRESH_SECRET` – for tokens
   - `MAIL_*` – for OTP emails (optional; OTP logs to console if not set)

2. Install and run:

```bash
pnpm install
pnpm run start:dev
```

Server runs at `http://localhost:3000` (or `PORT` from `.env`).

## API routes

Base URL: `http://localhost:3000`

| Method | Route | Body / Headers | Description |
|--------|--------|----------------|-------------|
| POST | `/auth/signup` | `{ name, contactNumber, email, password, role }` | Register; sends OTP email |
| POST | `/auth/verify-otp` | `{ email, otp }` | Verify email; returns access + refresh tokens |
| POST | `/auth/resend-otp` | `{ email }` | Resend OTP |
| POST | `/auth/login` | `{ email, password }` | Login (email must be verified) |
| POST | `/auth/refresh` | `{ refreshToken }` | New access token |
| POST | `/auth/logout` | `{ refreshToken }` | Invalidate refresh token |
| GET | `/auth/me` | `Authorization: Bearer <accessToken>` | Current user (protected) |

**Roles:** `user` \| `provider` \| `admin`

## Scripts

- `pnpm run start:dev` – development (watch)
- `pnpm run start` – run once
- `pnpm run build` – production build
