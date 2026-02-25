import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule, ConfigService } from '@nestjs/config';

@Module({
  imports: [
    TypeOrmModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: (configService: ConfigService) => ({
        type: 'postgres',
        url: configService.get<string>('database.url'),
        autoLoadEntities: true,
        synchronize: configService.get<string>('nodeEnv') === 'development',
        logging: configService.get<string>('nodeEnv') === 'development',
        ssl: { rejectUnauthorized: false },
        extra: {
          max: 20,
          idleTimeoutMillis: 10000,
          connectionTimeoutMillis: 5000,
        },
      }),
      inject: [ConfigService],
    }),
  ],
})
export class DatabaseModule {}
