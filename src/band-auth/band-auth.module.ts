import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';

import { BandAuthService } from './band-auth.service';
import { BandAuthController } from './band-auth.controller';
import { PrismaModule } from '../prisma/prisma.module';
import { MailModule } from '../mail/mail.module';
import { BandOtpModule } from '../band-otp/band-otp.module';

import { BandJwtAccessStrategy } from './strategies/band-jwt-access.strategy';
import { BandJwtRefreshStrategy } from './strategies/band-jwt-refresh.strategy';

@Module({
  imports: [
    PrismaModule,
    MailModule,
    BandOtpModule,
    PassportModule,
    JwtModule.register({}),
  ],
  controllers: [BandAuthController],
  providers: [
    BandAuthService,
    BandJwtAccessStrategy,
    BandJwtRefreshStrategy,
  ],
  exports: [BandAuthService],
})
export class BandAuthModule {}
