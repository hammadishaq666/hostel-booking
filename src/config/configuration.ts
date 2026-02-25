export default () => {
  const databaseUrl = process.env.DATABASE_URL;
  if (
    !databaseUrl ||
    databaseUrl.includes('[YOUR-PASSWORD]')
  ) {
    throw new Error(
      'DATABASE_URL must be set in .env with your actual database password (replace [YOUR-PASSWORD])',
    );
  }
  return {
    nodeEnv: process.env.NODE_ENV ?? 'development',
    port: parseInt(process.env.PORT ?? '3000', 10),
    supabase: {
      url: process.env.NEXT_PUBLIC_SUPABASE_URL,
      anonKey: process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY,
    },
    database: {
      url: databaseUrl,
    },
    jwt: {
      accessSecret: process.env.JWT_ACCESS_SECRET ?? 'change-me-in-production',
      accessExpiry: process.env.JWT_ACCESS_EXPIRY ?? '15m',
      refreshSecret: process.env.JWT_REFRESH_SECRET ?? 'change-me-refresh-in-production',
      refreshExpiry: process.env.JWT_REFRESH_EXPIRY ?? '7d',
    },
    otp: {
      expiryMinutes: parseInt(process.env.OTP_EXPIRY_MINUTES ?? '10', 10),
      length: 6,
    },
    mail: {
      host: process.env.MAIL_HOST ?? 'smtp.ethereal.email',
      port: parseInt(process.env.MAIL_PORT ?? '587', 10),
      secure: process.env.MAIL_SECURE === 'true',
      user: process.env.MAIL_USER,
      pass: process.env.MAIL_PASS,
      from: process.env.MAIL_FROM ?? 'noreply@hostel-booking.com',
    },
  };
};
