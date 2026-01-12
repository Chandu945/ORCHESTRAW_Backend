import { Injectable, BadRequestException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import * as bcrypt from 'bcrypt';
import { BandOtpPurpose } from '@prisma/client';

@Injectable()
export class BandOtpService {
  constructor(private readonly prisma: PrismaService) {}

  /**
   * Generate and send OTP
   */
  async generateAndStoreOtp(
    bandAccountId: string,
    purpose: BandOtpPurpose,
    expiryMinutes: number = 10,
  ): Promise<string> {
    // Generate 6-digit OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const codeHash = await bcrypt.hash(otp, 10);

    // Calculate expiration time
    const expiresAt = new Date(Date.now() + expiryMinutes * 60 * 1000);

    // Delete previous unused OTPs of same purpose
    await this.prisma.bandOtp.deleteMany({
      where: {
        bandAccountId,
        purpose,
        usedAt: null,
      },
    });

    // Create new OTP
    await this.prisma.bandOtp.create({
      data: {
        bandAccountId,
        purpose,
        codeHash,
        expiresAt,
        lastSentAt: new Date(),
      },
    });

    return otp;
  }

  /**
   * Verify OTP
   */
  async verifyOtp(
    bandAccountId: string,
    otp: string,
    purpose: BandOtpPurpose,
  ): Promise<boolean> {
    const bandOtpRecord = await this.prisma.bandOtp.findFirst({
      where: {
        bandAccountId,
        purpose,
        usedAt: null,
      },
      orderBy: {
        createdAt: 'desc',
      },
    });

    if (!bandOtpRecord) {
      throw new BadRequestException('No valid OTP found for this account');
    }

    // Check if OTP is expired
    if (new Date() > bandOtpRecord.expiresAt) {
      throw new BadRequestException('OTP has expired');
    }

    // Check attempts
    if (bandOtpRecord.attempts >= 5) {
      throw new BadRequestException(
        'Too many OTP verification attempts. Please request a new OTP.',
      );
    }

    // Verify OTP
    const isValid = await bcrypt.compare(otp, bandOtpRecord.codeHash);

    if (!isValid) {
      // Increment attempts
      await this.prisma.bandOtp.update({
        where: { id: bandOtpRecord.id },
        data: { attempts: { increment: 1 } },
      });

      throw new BadRequestException('Invalid OTP');
    }

    // Mark OTP as used
    await this.prisma.bandOtp.update({
      where: { id: bandOtpRecord.id },
      data: { usedAt: new Date() },
    });

    return true;
  }

  /**
   * Check if OTP can be resent (rate limiting)
   */
  async canResendOtp(
    bandAccountId: string,
    purpose: BandOtpPurpose,
    waitMinutes: number = 1,
  ): Promise<boolean> {
    const lastOtp = await this.prisma.bandOtp.findFirst({
      where: {
        bandAccountId,
        purpose,
      },
      orderBy: {
        lastSentAt: 'desc',
      },
    });

    if (!lastOtp || !lastOtp.lastSentAt) {
      return true;
    }

    const timeDiffMinutes =
      (Date.now() - lastOtp.lastSentAt.getTime()) / (1000 * 60);
    return timeDiffMinutes >= waitMinutes;
  }

  /**
   * Get time until OTP can be resent
   */
  async getResendWaitTime(
    bandAccountId: string,
    purpose: BandOtpPurpose,
    waitMinutes: number = 1,
  ): Promise<number> {
    const lastOtp = await this.prisma.bandOtp.findFirst({
      where: {
        bandAccountId,
        purpose,
      },
      orderBy: {
        lastSentAt: 'desc',
      },
    });

    if (!lastOtp || !lastOtp.lastSentAt) {
      return 0;
    }

    const timeDiffMinutes =
      (Date.now() - lastOtp.lastSentAt.getTime()) / (1000 * 60);
    const remainingMinutes = waitMinutes - timeDiffMinutes;

    return Math.max(0, Math.ceil(remainingMinutes));
  }

  /**
   * Clean up expired OTPs
   */
  async cleanupExpiredOtps(): Promise<void> {
    await this.prisma.bandOtp.deleteMany({
      where: {
        expiresAt: {
          lt: new Date(),
        },
      },
    });
  }
}
