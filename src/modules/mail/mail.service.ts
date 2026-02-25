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
      const port = this.configService.get<number>('mail.port', 587);
      const secure = this.configService.get<boolean>('mail.secure');
      this.transporter = nodemailer.createTransport({
        host: this.configService.get<string>('mail.host'),
        port,
        secure: secure ?? false,
        auth: { user, pass },
        ...(port === 587 && !secure ? { requireTLS: true } : {}),
      });
    }
    return this.transporter;
  }

  private getOtpEmailHtml(otp: string, expiryMinutes: number): string {
    const teal = '#008080';
    const tealDark = '#006666';
    const tealLight = '#E0F2F1';
    const tealMuted = '#80CBC4';
    const text = '#1a1a1a';
    const textMuted = '#5f5f5f';

    return `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Verify your account – Hostel Booking</title>
</head>
<body style="margin:0; padding:0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f5f5f5;">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background-color: #f5f5f5; padding: 40px 20px;">
    <tr>
      <td align="center">
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width: 480px; background-color: #ffffff; border-radius: 16px; overflow: hidden; box-shadow: 0 4px 24px rgba(0,0,0,0.08);">
          <!-- Header -->
          <tr>
            <td style="background-color: ${teal}; padding: 32px 32px 28px; text-align: center;">
              <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
                <tr>
                  <td align="center">
                    <div style="display: inline-block; width: 56px; height: 56px; background-color: rgba(255,255,255,0.2); border-radius: 14px; line-height: 56px; font-size: 28px; margin-bottom: 12px;">🏠</div>
                    <h1 style="margin: 0; color: #ffffff; font-size: 24px; font-weight: 700; letter-spacing: -0.5px;">Hostel Booking</h1>
                    <p style="margin: 6px 0 0; color: rgba(255,255,255,0.9); font-size: 14px;">Book your stay with confidence</p>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
          <!-- Content -->
          <tr>
            <td style="padding: 36px 32px 32px;">
              <p style="margin: 0 0 8px; color: ${text}; font-size: 18px; font-weight: 600;">Hi there 👋</p>
              <p style="margin: 0 0 24px; color: ${textMuted}; font-size: 15px; line-height: 1.5;">Thanks for signing up! Use the code below to verify your email and get started.</p>
              <!-- OTP Box -->
              <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
                <tr>
                  <td align="center" style="padding: 20px 0 28px;">
                    <div style="display: inline-block; background-color: ${tealLight}; border: 2px dashed ${teal}; border-radius: 12px; padding: 20px 32px;">
                      <p style="margin: 0; font-size: 13px; color: ${tealDark}; font-weight: 600; letter-spacing: 1px; text-transform: uppercase;">Your verification code</p>
                      <p style="margin: 10px 0 0; font-size: 32px; font-weight: 700; color: ${tealDark}; letter-spacing: 8px; font-family: 'Courier New', monospace;">${otp}</p>
                    </div>
                  </td>
                </tr>
              </table>
              <p style="margin: 0 0 6px; color: ${textMuted}; font-size: 13px;">⏱️ This code expires in <strong style="color: ${tealDark};">${expiryMinutes} minutes</strong>.</p>
              <p style="margin: 0 0 24px; color: ${textMuted}; font-size: 13px;">Enter it on the verification screen to complete your registration.</p>
              <!-- Security tip -->
              <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background-color: #f8faf8; border-radius: 10px; border-left: 4px solid ${teal};">
                <tr>
                  <td style="padding: 14px 16px;">
                    <p style="margin: 0; font-size: 13px; color: ${textMuted}; line-height: 1.5;">🔒 <strong style="color: ${text};">Security tip:</strong> We’ll never ask for this code by phone or email. Don’t share it with anyone.</p>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
          <!-- Footer -->
          <tr>
            <td style="padding: 20px 32px 24px; background-color: ${tealLight}; border-top: 1px solid ${tealMuted}; text-align: center;">
              <p style="margin: 0; font-size: 12px; color: ${textMuted};">You received this email because you signed up at <strong style="color: ${tealDark};">Hostel Booking</strong>.</p>
              <p style="margin: 6px 0 0; font-size: 12px; color: ${textMuted};">If you didn’t request this code, you can safely ignore this email.</p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>
`.trim();
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
    const expiryMinutes =
      this.configService.get<number>('otp.expiryMinutes') ?? 10;
    const from = this.configService.get<string>('mail.from');
    const transporter = this.getTransporter();
    await transporter.sendMail({
      from: from ?? 'noreply@hostel-booking.com',
      to: email,
      subject: 'Your Hostel Booking verification code',
      text: `Your Hostel Booking verification code is: ${otp}. It expires in ${expiryMinutes} minutes. Do not share this code with anyone.`,
      html: this.getOtpEmailHtml(otp, expiryMinutes),
    });
  }
}
