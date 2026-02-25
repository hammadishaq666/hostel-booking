import {
  Injectable,
  UnauthorizedException,
  ConflictException,
  BadRequestException,
  Logger,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';
import { User } from '../user/entities/user.entity';
import { UserService } from '../user/user.service';
import { MailService } from '../mail/mail.service';
import { RefreshToken } from './entities/refresh-token.entity';
import { SignupDto } from './dto/signup.dto';
import { LoginDto } from './dto/login.dto';
import { TokenPayload } from '../../common/types/auth.types';
import { Role } from '../../common/enums/role.enum';

/** 9 rounds: ~30–80ms per hash; 10 was ~50–150ms. Still secure for most apps. */
const SALT_ROUNDS = 9;

export type { TokenPayload };

export interface AuthTokens {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
  /** All roles this user has (for frontend dashboard picker when multiple). */
  roles: Role[];
}

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);
  private jwtConfig: {
    accessSecret: string;
    accessExpiry: string;
    refreshSecret: string;
    refreshExpiry: string;
  } | null = null;

  constructor(
    private readonly userService: UserService,
    private readonly mailService: MailService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    @InjectRepository(RefreshToken)
    private readonly refreshTokenRepo: Repository<RefreshToken>,
  ) {}

  private getJwtConfig() {
    if (!this.jwtConfig) {
      this.jwtConfig = {
        accessSecret: this.configService.get<string>('jwt.accessSecret')!,
        accessExpiry: this.configService.get<string>('jwt.accessExpiry')!,
        refreshSecret: this.configService.get<string>('jwt.refreshSecret')!,
        refreshExpiry: this.configService.get<string>('jwt.refreshExpiry')!,
      };
    }
    return this.jwtConfig;
  }

  async signup(dto: SignupDto): Promise<{ message: string; userId: string }> {
    const email = dto.email.toLowerCase();
    const existing = await this.userService.findByEmail(email);

    if (existing) {
      if (existing.roles.includes(dto.role)) {
        throw new ConflictException(
          `You are already registered as ${dto.role}. You can log in with this role.`,
        );
      }
      const valid = await bcrypt.compare(dto.password, existing.passwordHash);
      if (!valid) {
        throw new UnauthorizedException('Invalid password for this email');
      }
      existing.roles = [...existing.roles, dto.role];
      await this.userService.save(existing);
      return {
        message: `You can now log in as ${dto.role}. Use the same email and password.`,
        userId: existing.id,
      };
    }

    const passwordHash = await bcrypt.hash(dto.password, SALT_ROUNDS);
    const otp = this.generateOtp();
    const expiryMinutes = this.configService.get<number>('otp.expiryMinutes', 10);
    const otpExpiresAt = new Date(Date.now() + expiryMinutes * 60 * 1000);

    const saved = await this.userService.create({
      name: dto.name.trim(),
      contactNumber: dto.contactNumber.replace(/\s/g, ''),
      email,
      passwordHash,
      roles: [dto.role],
      emailVerified: false,
      otp,
      otpExpiresAt,
    });
    this.mailService.sendOtp(email, otp).catch((err) => {
      this.logger.warn(`Failed to send OTP email to ${email}: ${err?.message ?? err}`);
    });
    return {
      message: 'Verification code sent to your email',
      userId: saved.id,
    };
  }

  async verifyOtp(
    email: string,
    otp: string,
  ): Promise<AuthTokens> {
    const user = await this.userService.findByEmail(email.toLowerCase());
    if (!user) throw new UnauthorizedException('Invalid email or OTP');
    if (!user.otp || !user.otpExpiresAt) {
      throw new BadRequestException('No pending verification. Request a new code.');
    }
    if (user.otp !== otp) {
      throw new UnauthorizedException('Invalid OTP');
    }
    if (new Date() > user.otpExpiresAt) {
      throw new BadRequestException('OTP expired. Please request a new code.');
    }
    user.emailVerified = true;
    user.otp = null;
    user.otpExpiresAt = null;
    await this.userService.save(user);
    const roleForToken = user.roles[0];
    return this.issueTokens(user, roleForToken);
  }

  async login(dto: LoginDto): Promise<AuthTokens> {
    const user = await this.userService.findByEmail(dto.email.toLowerCase());
    if (!user) {
      throw new UnauthorizedException('Invalid email or password');
    }
    const valid = await bcrypt.compare(dto.password, user.passwordHash);
    if (!valid) {
      throw new UnauthorizedException('Invalid email or password');
    }
    if (!user.emailVerified) {
      throw new UnauthorizedException(
        'Please verify your email first. Check your inbox for the OTP.',
      );
    }

    let roleForToken: Role;
    if (user.roles.length === 1) {
      roleForToken = user.roles[0];
    } else {
      if (!dto.role || !user.roles.includes(dto.role)) {
        throw new BadRequestException(
          `Please specify which account to use. Your roles: ${user.roles.join(', ')}. Send "role" in the body (e.g. "user" or "provider").`,
        );
      }
      roleForToken = dto.role;
    }

    this.upgradeHashIfNeeded(user, dto.password);
    return this.issueTokens(user, roleForToken);
  }

  /** One-time upgrade: 12-round hashes → 10 rounds so next login is fast. Runs in background. */
  private upgradeHashIfNeeded(user: User, plainPassword: string): void {
    const is12Rounds =
      user.passwordHash.startsWith('$2a$12$') ||
      user.passwordHash.startsWith('$2b$12$');
    if (!is12Rounds) return;
    bcrypt.hash(plainPassword, 10).then((newHash) => {
      user.passwordHash = newHash;
      this.userService.save(user).catch((err) => {
        this.logger.warn(`Hash upgrade failed for ${user.email}: ${err?.message}`);
      });
    }).catch(() => {});
  }

  async refresh(refreshToken: string): Promise<AuthTokens> {
    const hash = this.hashToken(refreshToken);
    const stored = await this.refreshTokenRepo.findOne({
      where: { tokenHash: hash },
      relations: ['user'],
    });
    if (!stored || stored.expiresAt < new Date()) {
      if (stored) await this.refreshTokenRepo.remove(stored);
      throw new UnauthorizedException('Invalid or expired refresh token');
    }
    const payload = this.jwtService.decode(refreshToken) as TokenPayload | null;
    const role = payload?.role ?? stored.user.roles[0];
    return this.issueTokens(stored.user, role);
  }

  async logout(refreshToken: string): Promise<void> {
    const hash = this.hashToken(refreshToken);
    await this.refreshTokenRepo.delete({ tokenHash: hash });
  }

  async resendOtp(email: string): Promise<{ message: string }> {
    const user = await this.userService.findByEmail(email.toLowerCase());
    if (!user) {
      throw new BadRequestException('No account found with this email');
    }
    if (user.emailVerified) {
      throw new BadRequestException('Email is already verified. You can log in.');
    }
    const otp = this.generateOtp();
    const expiryMinutes = this.configService.get<number>('otp.expiryMinutes', 10);
    user.otp = otp;
    user.otpExpiresAt = new Date(Date.now() + expiryMinutes * 60 * 1000);
    await this.userService.save(user);
    this.mailService.sendOtp(email, otp).catch((err) => {
      this.logger.warn(`Failed to send OTP email to ${email}: ${err?.message ?? err}`);
    });
    return { message: 'Verification code sent' };
  }

  private issueTokens(user: User, role: Role): Promise<AuthTokens> {
    const payload: Omit<TokenPayload, 'type'> = {
      sub: user.id,
      email: user.email,
      role,
    };
    const { accessSecret, accessExpiry, refreshSecret, refreshExpiry } =
      this.getJwtConfig();

    const accessToken = this.jwtService.sign(
      { ...payload, type: 'access' },
      { secret: accessSecret, expiresIn: accessExpiry },
    );
    const refreshToken = this.jwtService.sign(
      { ...payload, type: 'refresh' },
      { secret: refreshSecret, expiresIn: refreshExpiry },
    );

    const decoded = this.jwtService.decode(accessToken) as { exp: number };
    const expiresIn = decoded?.exp
      ? Math.max(0, decoded.exp - Math.floor(Date.now() / 1000))
      : 900;

    return this.saveRefreshToken(user.id, refreshToken, refreshExpiry).then(
      () => ({
        accessToken,
        refreshToken,
        expiresIn,
        roles: user.roles,
      }),
    );
  }

  private async saveRefreshToken(
    userId: string,
    token: string,
    refreshExpiry: string,
  ): Promise<void> {
    const decoded = this.jwtService.decode(token) as { exp: number };
    const expiresAt = decoded?.exp
      ? new Date(decoded.exp * 1000)
      : new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
    await this.refreshTokenRepo.insert({
      userId,
      tokenHash: this.hashToken(token),
      expiresAt,
    });
  }

  private generateOtp(): string {
    const length = this.configService.get<number>('otp.length', 6);
    const max = 10 ** length - 1;
    const n = crypto.randomInt(0, max + 1);
    return n.toString().padStart(length, '0');
  }

  private hashToken(token: string): string {
    return crypto.createHash('sha256').update(token).digest('hex');
  }
}
