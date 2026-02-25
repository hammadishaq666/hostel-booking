<p align="center">
  <a href="http://nestjs.com/" target="blank"><img src="https://nestjs.com/img/logo-small.svg" width="120" alt="Nest Logo" /></a>
</p>

[circleci-image]: https://img.shields.io/circleci/build/github/nestjs/nest/master?token=abc123def456
[circleci-url]: https://circleci.com/gh/nestjs/nest

  <p align="center">A progressive <a href="http://nodejs.org" target="_blank">Node.js</a> framework for building efficient and scalable server-side applications.</p>
    <p align="center">
<a href="https://www.npmjs.com/~nestjscore" target="_blank"><img src="https://img.shields.io/npm/v/@nestjs/core.svg" alt="NPM Version" /></a>
<a href="https://www.npmjs.com/~nestjscore" target="_blank"><img src="https://img.shields.io/npm/l/@nestjs/core.svg" alt="Package License" /></a>
<a href="https://www.npmjs.com/~nestjscore" target="_blank"><img src="https://img.shields.io/npm/dm/@nestjs/common.svg" alt="NPM Downloads" /></a>
<a href="https://circleci.com/gh/nestjs/nest" target="_blank"><img src="https://img.shields.io/circleci/build/github/nestjs/nest/master" alt="CircleCI" /></a>
<a href="https://discord.gg/G7Qnnhy" target="_blank"><img src="https://img.shields.io/badge/discord-online-brightgreen.svg" alt="Discord"/></a>
<a href="https://opencollective.com/nest#backer" target="_blank"><img src="https://opencollective.com/nest/backers/badge.svg" alt="Backers on Open Collective" /></a>
<a href="https://opencollective.com/nest#sponsor" target="_blank"><img src="https://opencollective.com/nest/sponsors/badge.svg" alt="Sponsors on Open Collective" /></a>
  <a href="https://paypal.me/kamilmysliwiec" target="_blank"><img src="https://img.shields.io/badge/Donate-PayPal-ff3f59.svg" alt="Donate us"/></a>
    <a href="https://opencollective.com/nest#sponsor"  target="_blank"><img src="https://img.shields.io/badge/Support%20us-Open%20Collective-41B883.svg" alt="Support us"></a>
  <a href="https://twitter.com/nestframework" target="_blank"><img src="https://img.shields.io/twitter/follow/nestframework.svg?style=social&label=Follow" alt="Follow us on Twitter"></a>
</p>
  <!--[![Backers on Open Collective](https://opencollective.com/nest/backers/badge.svg)](https://opencollective.com/nest#backer)
  [![Sponsors on Open Collective](https://opencollective.com/nest/sponsors/badge.svg)](https://opencollective.com/nest#sponsor)-->

## Description

[Nest](https://github.com/nestjs/nest) framework TypeScript starter repository.

## Architecture

The project follows a **modular NestJS architecture** and uses **TypeORM** for the database layer.

- **Root:** `AppModule` imports global config, database, and feature modules.
- **Database:** `DatabaseModule` configures TypeORM (PostgreSQL) with `autoLoadEntities`. Entities are registered per module via `TypeOrmModule.forFeature()`.
- **Feature modules** (`src/modules/`): Each domain is a self-contained module (e.g. `AuthModule`, `UserModule`, `MailModule`) with its own controller, service, DTOs, and entities.
- **Shared:** `src/common/` holds decorators, guards, enums, and types; `src/config/` and `src/database/` for app-wide config and DB connection.

## Project setup

1. **Environment**: Copy `.env.example` to `.env` and set your Supabase credentials. Replace `[YOUR-PASSWORD]` in `DATABASE_URL` with your Supabase database password (Settings → Database).

2. **Install dependencies**:

```bash
$ pnpm install
```

### Database connection: `getaddrinfo ENOTFOUND db....supabase.co`

The database hostname is not resolving (DNS/network). Try these in order:

---

**1. Use Supabase Connection Pooler (different hostname – often works when direct fails)**

In [Supabase Dashboard](https://supabase.com/dashboard) → your project → **Settings** → **Database**:

- Find the **Connection string** section.
- Switch to **“Connection pooling”** (or “Session pooler” / “Transaction pooler”).
- Copy the **URI** (it will use a host like `aws-0-<region>.pooler.supabase.com` instead of `db....supabase.co`).
- In your `.env`, set `DATABASE_URL` to this **pooler URI** (replace the password placeholder with your DB password).
- Restart the app: `pnpm run start:dev`.

The pooler host often resolves even when `db.*.supabase.co` does not on affected ISPs.

---

**2. Change system DNS, then flush and restart**

| Provider   | Preferred   | Alternate   |
|-----------|-------------|-------------|
| Google    | `8.8.8.8`   | `8.8.4.4`   |
| Cloudflare| `1.1.1.1`   | `1.0.0.1`   |

- **Windows:** Settings → Network & Internet → Wi‑Fi/Ethernet → your connection → **Edit** (DNS) → **Manual** → set the above.
- **Flush DNS:** Open **PowerShell as Administrator**, run:  
  `ipconfig /flushdns`
- **Fully close** all terminals and Cursor (or your IDE), then reopen the project and run `pnpm run start:dev` again. Node uses DNS at process start, so a full restart is required.

---

**3. VPN**

Use a VPN with an exit node outside India; Supabase is reachable from other regions.

## Authentication

Roles: **user**, **provider**, **admin**.

| Endpoint | Body | Description |
|----------|------|-------------|
| `POST /auth/signup` | `{ email, password, role }` | Register; sends OTP to email |
| `POST /auth/verify-otp` | `{ email, otp }` | Verify email, returns access + refresh tokens |
| `POST /auth/resend-otp` | `{ email }` | Resend verification code |
| `POST /auth/login` | `{ email, password }` | Login (email must be verified) |
| `POST /auth/refresh` | `{ refreshToken }` | New access token |
| `POST /auth/logout` | `{ refreshToken }` | Invalidate refresh token |
| `GET /auth/me` | `Authorization: Bearer <accessToken>` | Current user (protected) |

**Role-based access:** Use `@UseGuards(JwtAuthGuard, RolesGuard)` and `@Roles(Role.ADMIN)` (or `Role.PROVIDER`, `Role.USER`) on controllers or handlers. Set `JWT_ACCESS_SECRET`, `JWT_REFRESH_SECRET`, and optionally `MAIL_*` in `.env` (see `.env.example`).

## Compile and run the project

```bash
# development
$ pnpm run start

# watch mode
$ pnpm run start:dev

# production mode
$ pnpm run start:prod
```

## Run tests

```bash
# unit tests
$ pnpm run test

# e2e tests
$ pnpm run test:e2e

# test coverage
$ pnpm run test:cov
```

## Deployment

When you're ready to deploy your NestJS application to production, there are some key steps you can take to ensure it runs as efficiently as possible. Check out the [deployment documentation](https://docs.nestjs.com/deployment) for more information.

If you are looking for a cloud-based platform to deploy your NestJS application, check out [Mau](https://mau.nestjs.com), our official platform for deploying NestJS applications on AWS. Mau makes deployment straightforward and fast, requiring just a few simple steps:

```bash
$ pnpm install -g @nestjs/mau
$ mau deploy
```

With Mau, you can deploy your application in just a few clicks, allowing you to focus on building features rather than managing infrastructure.

## Resources

Check out a few resources that may come in handy when working with NestJS:

- Visit the [NestJS Documentation](https://docs.nestjs.com) to learn more about the framework.
- For questions and support, please visit our [Discord channel](https://discord.gg/G7Qnnhy).
- To dive deeper and get more hands-on experience, check out our official video [courses](https://courses.nestjs.com/).
- Deploy your application to AWS with the help of [NestJS Mau](https://mau.nestjs.com) in just a few clicks.
- Visualize your application graph and interact with the NestJS application in real-time using [NestJS Devtools](https://devtools.nestjs.com).
- Need help with your project (part-time to full-time)? Check out our official [enterprise support](https://enterprise.nestjs.com).
- To stay in the loop and get updates, follow us on [X](https://x.com/nestframework) and [LinkedIn](https://linkedin.com/company/nestjs).
- Looking for a job, or have a job to offer? Check out our official [Jobs board](https://jobs.nestjs.com).

## Support

Nest is an MIT-licensed open source project. It can grow thanks to the sponsors and support by the amazing backers. If you'd like to join them, please [read more here](https://docs.nestjs.com/support).

## Stay in touch

- Author - [Kamil Myśliwiec](https://twitter.com/kammysliwiec)
- Website - [https://nestjs.com](https://nestjs.com/)
- Twitter - [@nestframework](https://twitter.com/nestframework)

## License

Nest is [MIT licensed](https://github.com/nestjs/nest/blob/master/LICENSE).
