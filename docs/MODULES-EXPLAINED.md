# How `src/modules` Works – Simple Guide

This doc explains how your NestJS app is structured and how a request flows from the URL to the database and back.

---

## 1. How the app starts

```
main.ts  →  creates app from AppModule  →  listens on port 3000
```

**`src/main.ts`**
- Creates the NestJS app using `AppModule`.
- Adds a global `ValidationPipe`: every request body is checked with the DTO validators (e.g. `@IsEmail()`, `@MinLength(8)`).
- Starts the HTTP server on `PORT` (default 3000).

**`src/app.module.ts`**
- This is the **root module**. It **imports** other modules and registers the root controller/service.
- **Imports:** `ConfigModule`, `DatabaseModule`, `MailModule`, `UserModule`, `AuthModule`.
- **Controllers:** `AppController` (e.g. health or home).
- **Providers:** `AppService`.

So at startup: Nest loads `AppModule` → loads each imported module → wires dependencies (dependency injection) → your routes are ready.

---

## 2. What is a “module”?

A **module** is a box that groups related pieces:

- **Controllers** – handle HTTP (routes).
- **Providers / Services** – business logic (and other injectables).
- **Imports** – other modules this module depends on.
- **Exports** – what this module exposes to others (e.g. `UserService` so `AuthModule` can use it).

When you **import** a module, you can use what that module **exports**.  
Example: `AuthModule` imports `UserModule` → so `AuthService` can inject `UserService`.

---

## 3. The three modules under `src/modules`

You have three feature modules:

| Module   | Folder        | Purpose                                      |
|----------|----------------|----------------------------------------------|
| **Auth** | `modules/auth` | Signup, login, OTP, refresh, logout, /me      |
| **User** | `modules/user` | Create/find/save users (used by Auth)        |
| **Mail** | `modules/mail` | Send emails (e.g. OTP)                       |

---

## 4. MailModule – sending emails

**Files:** `mail.module.ts`, `mail.service.ts`, `index.ts`

**`mail.module.ts`**
- `@Global()`: MailModule is registered once and `MailService` is available everywhere without importing `MailModule` in each feature.
- **Providers:** `MailService`.
- **Exports:** `MailService` so any module can inject it.

**`mail.service.ts`**
- **Constructor:** Gets `ConfigService` (to read `MAIL_*` from config).
- **Responsibility:** Build a nodemailer transporter (SMTP) and send emails.
- **Main method:** `sendOtp(email, otp)` – sends the OTP email (HTML template + plain text).

So: **MailModule** = “we have a global service that can send emails.” No routes; only used by other services (e.g. Auth).

---

## 5. UserModule – user data (database)

**Files:** `user.module.ts`, `user.service.ts`, `entities/user.entity.ts`, `index.ts`

**`user.module.ts`**
- **Imports:** `TypeOrmModule.forFeature([User])` – registers the `User` entity and a repository for it in this module.
- **Providers:** `UserService`.
- **Exports:** `UserService` – so other modules (e.g. Auth) can inject it.

**`user.service.ts`**
- **Constructor:** Injects `Repository<User>` (TypeORM repo for the `users` table).
- **Methods:**
  - `findByEmail(email)` – find one user by email.
  - `findById(id)` – find one user by id.
  - `create(data)` – create a new user (signup).
  - `save(user)` – update an existing user (e.g. after OTP verify, or hash upgrade).

So: **UserModule** = “we have a service that talks to the `users` table.” No HTTP routes; used by Auth.

**`entities/user.entity.ts`**
- TypeORM **entity**: describes the `users` table (columns, types, relations).
- Decorators like `@Entity('users')`, `@Column()`, `@PrimaryGeneratedColumn('uuid')` map the class to the database.
- **Relation:** One user has many `RefreshToken` (`@OneToMany`).

---

## 6. AuthModule – login, signup, tokens, protected route

**Files:**  
`auth.module.ts`, `auth.controller.ts`, `auth.service.ts`,  
`entities/refresh-token.entity.ts`,  
`dto/*.ts` (signup, login, verify-otp, resend-otp, refresh-token),  
`strategies/jwt.strategy.ts`,  
`index.ts`

### 6.1 `auth.module.ts`

- **Imports:**
  - `UserModule` – to use `UserService`.
  - `TypeOrmModule.forFeature([RefreshToken])` – repository for refresh tokens.
  - `PassportModule` + `JwtModule` – JWT creation and validation.
  - `ConfigModule` – for JWT secrets and expiry.
- **Controllers:** `AuthController` (all auth routes).
- **Providers:** `AuthService`, `JwtStrategy`.
- **Exports:** `AuthService` (in case other modules need it).

So: **AuthModule** = “we have auth routes and logic; we use User, RefreshToken, JWT, and Config.”

### 6.2 `auth.controller.ts`

- **Base path:** `@Controller('auth')` → all routes start with `/auth`.

| Method | Route         | What it does                          |
|--------|---------------|----------------------------------------|
| POST   | `/auth/signup`     | Register; sends OTP email              |
| POST   | `/auth/verify-otp` | Verify OTP, then return tokens        |
| POST   | `/auth/resend-otp` | Resend OTP                            |
| POST   | `/auth/login`      | Login (email + password) → tokens     |
| POST   | `/auth/refresh`   | New access token from refresh token   |
| POST   | `/auth/logout`    | Invalidate refresh token              |
| GET    | `/auth/me`        | Current user (needs JWT)              |

- **Constructor:** Injects `AuthService` and `UserService`.
- **Example:** `@Post('signup') async signup(@Body() dto: SignupDto)`  
  - Body is validated by `ValidationPipe` using `SignupDto` (email, password, name, contactNumber, role).  
  - Then `authService.signup(dto)` runs.

- **Protected route:** `@Get('me')` uses `@UseGuards(JwtAuthGuard)` and `@CurrentUser() payload`.  
  - Only requests with a valid JWT in `Authorization: Bearer <token>` reach the handler; `payload` is the decoded token (e.g. `sub`, `email`, `role`).

### 6.3 `auth.service.ts`

- **Constructor:** Injects `UserService`, `MailService`, `JwtService`, `ConfigService`, and `Repository<RefreshToken>`.
- **Main methods:**
  - **signup(dto):** Check email not taken → hash password (bcrypt) → create user (via `UserService`) with OTP → send OTP email (non-blocking) → return message + userId.
  - **verifyOtp(email, otp):** Find user → check OTP and expiry → set `emailVerified`, clear OTP → issue tokens.
  - **login(dto):** Find user → bcrypt.compare → check email verified → optionally upgrade old hash → issue tokens.
  - **refresh(refreshToken):** Find stored refresh token by hash → check not expired → issue new tokens.
  - **logout(refreshToken):** Delete refresh token by hash.
  - **resendOtp(email):** Find user → generate new OTP → save → send OTP email (non-blocking).

- **issueTokens(user):** Build JWT payload → sign access + refresh tokens → save refresh token in DB → return `{ accessToken, refreshToken, expiresIn }`.

So: **AuthService** = “all auth business logic: signup, OTP, login, refresh, logout,” using User, Mail, JWT, and RefreshToken repository.

### 6.4 DTOs (`auth/dto/*.ts`)

- **SignupDto:** `name`, `contactNumber`, `email`, `password`, `role` – with class-validator decorators (`@IsEmail()`, `@MinLength(8)`, etc.). Used for `POST /auth/signup`.
- **LoginDto:** `email`, `password`. Used for `POST /auth/login`.
- **VerifyOtpDto:** `email`, `otp`. Used for `POST /auth/verify-otp`.
- **ResendOtpDto:** `email`. Used for `POST /auth/resend-otp`.
- **RefreshTokenDto:** `refreshToken`. Used for refresh and logout.

ValidationPipe runs before the controller method; invalid body → 400 with validation errors.

### 6.5 `strategies/jwt.strategy.ts`

- **Purpose:** Tells Passport how to validate a JWT for the `'jwt'` strategy.
- **Config:** Take JWT from `Authorization: Bearer <token>`, use `jwt.accessSecret`, do not ignore expiration.
- **validate(payload):** If `payload.type === 'access'`, return payload; otherwise throw.  
  The returned value is attached to `request.user` and is what `@CurrentUser()` reads.

So: **JwtStrategy** = “for routes that use JwtAuthGuard, get the user from the JWT and put it on `request.user`.”

### 6.6 `entities/refresh-token.entity.ts`

- TypeORM entity for table `refresh_tokens`: `id`, `user_id`, `token_hash`, `expires_at`, `created_at`.
- **Relation:** ManyToOne to `User`. Used to store refresh tokens and validate them on `/auth/refresh` and logout.

---

## 7. One full request example: POST /auth/signup

1. **HTTP:** Client sends `POST http://localhost:3000/auth/signup` with JSON body `{ name, contactNumber, email, password, role }`.

2. **Validation:** Global `ValidationPipe` runs and validates the body with `SignupDto`. If invalid → 400.

3. **Routing:** Nest matches the request to `AuthController.signup(@Body() dto: SignupDto)`.

4. **Controller:** Calls `this.authService.signup(dto)`.

5. **AuthService.signup:**
   - Normalizes email (e.g. lower case).
   - Calls `userService.findByEmail(email)` → if user exists, throw conflict.
   - Hashes password with bcrypt.
   - Generates OTP and expiry.
   - Calls `userService.create({ name, contactNumber, email, passwordHash, role, emailVerified: false, otp, otpExpiresAt })` → **UserService** uses TypeORM to insert into `users`.
   - Calls `mailService.sendOtp(email, otp)` in the background (does not wait).
   - Returns `{ message, userId }`.

6. **Response:** Nest sends that JSON back to the client.

So: **Controller** = entry point; **Service** = logic; **UserService** = DB for users; **MailService** = send email. All wired by Nest via modules and dependency injection.

---

## 8. Dependency injection in one sentence

When you write `constructor(private readonly authService: AuthService) { }` in `AuthController`, Nest creates (or reuses) an instance of `AuthService` and injects it. Nest can do that because `AuthService` is a **provider** in a module that is in the app (and `AuthService` itself gets `UserService`, `MailService`, etc., the same way). You never do `new AuthService(...)` yourself.

---

## 9. File-by-file summary

| File | Role |
|------|------|
| **main.ts** | Bootstrap app from AppModule, global ValidationPipe, listen on port. |
| **app.module.ts** | Root module: imports Config, Database, Mail, User, Auth. |
| **modules/mail** | MailModule (global); MailService sends emails (e.g. OTP). |
| **modules/user** | UserModule; UserService (create/find/save user); User entity. |
| **modules/auth** | AuthModule; AuthController (routes); AuthService (signup/login/OTP/tokens); DTOs; JwtStrategy; RefreshToken entity. |

That’s how `src/modules` is structured and how the code works end to end.
