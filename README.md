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
| POST | `/auth/signup` | `{ name, contactNumber, email, password, role }` | Register as **user** or **provider**. Same email can sign up again with the other role (same password). |
| POST | `/auth/verify-otp` | `{ email, otp }` | Verify email; returns `{ accessToken, refreshToken, expiresIn, roles }` |
| POST | `/auth/resend-otp` | `{ email }` | Resend OTP |
| POST | `/auth/login` | `{ email, password, role? }` | Login. If account has both user + provider, send **role** (`"user"` or `"provider"`) to get tokens for that dashboard. Response includes **roles** array. |
| POST | `/auth/refresh` | `{ refreshToken }` | New access token (same role) |
| POST | `/auth/logout` | `{ refreshToken }` | Invalidate refresh token |
| GET | `/auth/me` | `Authorization: Bearer <accessToken>` | Current user: **role** (current), **roles** (all), profile fields |

**Roles:** `user` \| `provider` \| `admin`. One email can have **user** and **provider**; frontend uses **role** from token to show user vs provider dashboard.

## Scripts

- `pnpm run start:dev` – development (watch)
- `pnpm run start` – run once
- `pnpm run build` – production build
