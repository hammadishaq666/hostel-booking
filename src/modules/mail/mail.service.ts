import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as nodemailer from 'nodemailer';
import type { Transporter } from 'nodemailer';

@Injectable()
export class MailService {
  private transporter: Transporter | null = null;

  constructor(private readonly configService: ConfigService) {}

  private getTransporter(): Transporter {
    if (!this.transporter) {
      const user = this.configService.get<string>('mail.user');
      const pass = this.configService.get<string>('mail.pass');
      if (!user || !pass) throw new Error('Mail not configured');
      this.transporter = nodemailer.createTransport({
        host: this.configService.get<string>('mail.host'),
        port: this.configService.get<number>('mail.port'),
        secure: this.configService.get<boolean>('mail.secure'),
        auth: { user, pass },
      });
    }
    return this.transporter;
  }

  async sendOtp(email: string, otp: string): Promise<void> {
    const user = this.configService.get<string>('mail.user');
    const pass = this.configService.get<string>('mail.pass');
    if (!user || !pass) {
      console.warn(
        `[Mail] MAIL_USER/MAIL_PASS not set. OTP for ${email}: ${otp}`,
      );
      return;
    }
    const from = this.configService.get<string>('mail.from');
    const transporter = this.getTransporter();
    await transporter.sendMail({
      from: from ?? 'noreply@hostel-booking.com',
      to: email,
      subject: 'Your verification code',
      text: `Your OTP is: ${otp}. It expires in ${this.configService.get<number>('otp.expiryMinutes')} minutes.`,
      html: `
        <p>Your verification code is: <strong>${otp}</strong></p>
        <p>It expires in ${this.configService.get<number>('otp.expiryMinutes')} minutes. Do not share this code.</p>
      `,
    });
  }
}
