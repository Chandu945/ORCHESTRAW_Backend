import { Module } from '@nestjs/common';
import { BandOtpService } from './band-otp.service';
import { PrismaModule } from '../prisma/prisma.module';

@Module({
  imports: [PrismaModule],
  providers: [BandOtpService],
  exports: [BandOtpService],
})
export class BandOtpModule {}
