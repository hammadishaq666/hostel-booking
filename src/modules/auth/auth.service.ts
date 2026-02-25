import {
  Injectable,
  UnauthorizedException,
  ConflictException,
  BadRequestException,
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
import { Role } from '../../common/enums/role.enum';
import { TokenPayload } from '../../common/types/auth.types';

const SALT_ROUNDS = 12;

export type { TokenPayload };

export interface AuthTokens {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

@Injectable()
export class AuthService {
  constructor(
    private readonly userService: UserService,
    private readonly mailService: MailService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    @InjectRepository(RefreshToken)
    private readonly refreshTokenRepo: Repository<RefreshToken>,
  ) {}

  async signup(dto: SignupDto): Promise<{ message: string; userId: string }> {
    const email = dto.email.toLowerCase();
    const existing = await this.userService.findByEmail(email);
    if (existing) {
      throw new ConflictException('An account with this email already exists');
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
      role: dto.role,
      emailVerified: false,
      otp,
      otpExpiresAt,
    });
    await this.mailService.sendOtp(email, otp);
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
    return this.issueTokens(user);
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
    return this.issueTokens(user);
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
    return this.issueTokens(stored.user);
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
    await this.mailService.sendOtp(email, otp);
    return { message: 'Verification code sent' };
  }

  private issueTokens(user: User): Promise<AuthTokens> {
    const payload: Omit<TokenPayload, 'type'> = {
      sub: user.id,
      email: user.email,
      role: user.role,
    };
    const accessSecret = this.configService.get<string>('jwt.accessSecret');
    const accessExpiry = this.configService.get<string>('jwt.accessExpiry');
    const refreshSecret = this.configService.get<string>('jwt.refreshSecret');
    const refreshExpiry = this.configService.get<string>('jwt.refreshExpiry');

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

    return this.saveRefreshToken(user.id, refreshToken).then(() => ({
      accessToken,
      refreshToken,
      expiresIn,
    }));
  }

  private async saveRefreshToken(
    userId: string,
    token: string,
  ): Promise<void> {
    const refreshExpiry = this.configService.get<string>('jwt.refreshExpiry');
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
