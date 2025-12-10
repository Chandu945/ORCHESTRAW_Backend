import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { ThrottlerModule } from '@nestjs/throttler';
import { ThrottlerStorageRedisService } from '@nest-lab/throttler-storage-redis';

import { APP_FILTER } from '@nestjs/core';
import { AllExceptionsFilter } from './common/filters/all-exceptions.filter';

import { PrismaModule } from './prisma/prisma.module';
import { UsersModule } from './users/users.module';
import { AuthModule } from './auth/auth.module';
import { MailModule } from './mail/mail.module';
import { AdminModule } from './admin/admin.module';

@Module({
  imports: [
    // ------------------------------------------------------------
    // GLOBAL CONFIG MODULE
    // ------------------------------------------------------------
    ConfigModule.forRoot({
      isGlobal: true,
    }),

    // ------------------------------------------------------------
    // GLOBAL THROTTLER CONFIG (Redis Storage)
    // ------------------------------------------------------------
    ThrottlerModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],

      useFactory: (config: ConfigService) => ({
        // ------------------------------------------------------------
        // Named throttler profiles (usable in @Throttle decorators)
        // ------------------------------------------------------------
        throttlers: [
          // Strict throttler → OTP + Login
          {
            name: 'short',
            ttl: 60000, // 1 minute
            limit: 3, // 3 requests per minute
          },

          // Medium throttler → refresh tokens, register, reset password
          {
            name: 'medium',
            ttl: 10000, // 10 seconds
            limit: 20, // 20 requests per 10 seconds
          },

          // Long throttler → public & safe endpoints
          {
            name: 'long',
            ttl: 60000, // 1 minute
            limit: 100, // 100 requests per minute
          },
        ],

        // ------------------------------------------------------------
        // REDIS STORAGE CONFIGURATION
        // ------------------------------------------------------------
        storage: new ThrottlerStorageRedisService(
          config.get<string>('REDIS_URL'), // e.g. redis://localhost:6379
        ),
      }),
    }),

    // ------------------------------------------------------------
    // PROJECT MODULES
    // ------------------------------------------------------------
    PrismaModule,
    UsersModule,
    AuthModule,
    MailModule,
    AdminModule,
  ],

  // ------------------------------------------------------------
  // GLOBAL PROVIDERS (Exception Filter, etc.)
  // ------------------------------------------------------------
  providers: [
    {
      provide: APP_FILTER,
      useClass: AllExceptionsFilter,
    },
  ],
})
export class AppModule {}