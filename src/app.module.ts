import { Module, OnModuleInit } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
// import { ThrottlerModule } from '@nestjs/throttler';
// import { ThrottlerStorageRedisService } from '@nest-lab/throttler-storage-redis';

import { APP_FILTER } from '@nestjs/core';
import { AllExceptionsFilter } from './common/filters/all-exceptions.filter';

import { PrismaModule } from './prisma/prisma.module';
import { UsersModule } from './users/users.module';
import { AuthModule } from './auth/auth.module';
import { MailModule } from './mail/mail.module';
import { AdminModule } from './admin/admin.module';
import { SeedModule } from './seed/seed.module';
import { SeedService } from './seed/seed.service';
import { OrchestrawAuthModule } from './orchestraw-auth/orchestraw-auth.module';

@Module({
  imports: [
    // ------------------------------------------------------------
    // GLOBAL CONFIG MODULE
    // ------------------------------------------------------------
    ConfigModule.forRoot({
      isGlobal: true,
    }),


    // ------------------------------------------------------------
    // PROJECT MODULES
    // ------------------------------------------------------------
    PrismaModule,
    UsersModule,
    AuthModule,
    MailModule,
    AdminModule,
    SeedModule,
    OrchestrawAuthModule,
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
export class AppModule implements OnModuleInit {
  constructor(private readonly seedService: SeedService) {}

  async onModuleInit() {
    await this.seedService.seedAdmins();
  }
}