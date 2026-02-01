import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { ConfigModule } from '@nestjs/config';
import { OrchestrawAuthService } from './orchestraw-auth.service';
import { OrchestrawAuthController } from './orchestraw-auth.controller';
import { PrismaModule } from '../prisma/prisma.module';
import { MailModule } from '../mail/mail.module';
import { OrchestrawJwtAccessStrategy } from './strategies/orchestraw-jwt-access.strategy';
import { OrchestrawJwtRefreshStrategy } from './strategies/orchestraw-jwt-refresh.strategy';
import { OrchestrawEmailVerifyStrategy } from './strategies/orchestraw-email-verify.strategy';
import { OrchestrawGoogleStrategy } from './strategies/orchestraw-google.strategy';
import { OrchestrawFacebookStrategy } from './strategies/orchestraw-facebook.strategy';
import { OrchestrawAccessGuard } from './guards/orchestraw-access.guard';
import { OrchestrawRefreshGuard } from './guards/orchestraw-refresh.guard';
import { OrchestrawEmailVerifyGuard } from './guards/orchestraw-email-verify.guard';
import { OrchestrawGoogleGuard } from './guards/orchestraw-google.guard';
import { OrchestrawFacebookGuard } from './guards/orchestraw-facebook.guard';
import { OrchestrawOtpService } from './orchestraw-otp.service';

@Module({
  imports: [
    ConfigModule,
    PassportModule,
    JwtModule.register({}),
    PrismaModule,
    MailModule,
  ],
  controllers: [OrchestrawAuthController],
  providers: [
    OrchestrawAuthService,
    OrchestrawOtpService,
    OrchestrawJwtAccessStrategy,
    OrchestrawJwtRefreshStrategy,
    OrchestrawEmailVerifyStrategy,
    OrchestrawGoogleStrategy,
    OrchestrawFacebookStrategy,
    OrchestrawAccessGuard,
    OrchestrawRefreshGuard,
    OrchestrawEmailVerifyGuard,
    OrchestrawGoogleGuard,
    OrchestrawFacebookGuard,
  ],
  exports: [OrchestrawAuthService],
})
export class OrchestrawAuthModule {}
