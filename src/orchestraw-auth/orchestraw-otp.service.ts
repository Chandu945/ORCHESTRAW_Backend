import { Injectable } from '@nestjs/common';
import * as crypto from 'crypto';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class OrchestrawOtpService {
  constructor(private prisma: PrismaService) {}

  /**
   * Generate a random 6-digit OTP
   */
  generateOtpCode(): string {
    return Math.floor(100000 + Math.random() * 900000).toString();
  }

  /**
   * Hash OTP code using SHA256
   */
  hashOtpCode(code: string): string {
    return crypto.createHash('sha256').update(code).digest('hex');
  }

  /**
   * Create OTP for email verification or password reset
   * Invalidates any previous OTPs for same email/purpose
   */
  async createOtp(
    email: string,
    purpose: 'EMAIL_VERIFY' | 'PASSWORD_RESET',
    expiryMinutes: number = 10,
  ): Promise<{ code: string; expiresAt: Date }> {
    // Delete expired OTPs for this email/purpose
    await this.prisma.orchestrawOtp.deleteMany({
      where: {
        email,
        purpose,
        expiresAt: {
          lt: new Date(),
        },
      },
    });

    const code = this.generateOtpCode();
    const codeHash = this.hashOtpCode(code);
    const expiresAt = new Date(Date.now() + expiryMinutes * 60 * 1000);
    const now = new Date();

    // Create new OTP record
    await this.prisma.orchestrawOtp.create({
      data: {
        email,
        purpose,
        codeHash,
        expiresAt,
        lastSentAt: now,
        attempts: 0,
      },
    });

    return { code, expiresAt };
  }

  /**
   * Verify OTP and mark as used
   */
  async verifyOtp(
    email: string,
    code: string,
    purpose: 'EMAIL_VERIFY' | 'PASSWORD_RESET',
    maxAttempts: number = 5,
  ): Promise<{ success: boolean; error?: string }> {
    const codeHash = this.hashOtpCode(code);
    const now = new Date();

    // Find latest OTP for this email/purpose
    const otp = await this.prisma.orchestrawOtp.findFirst({
      where: {
        email,
        purpose,
      },
      orderBy: {
        createdAt: 'desc',
      },
    });

    if (!otp) {
      return { success: false, error: 'OTP not found' };
    }

    // Check if OTP is expired
    if (otp.expiresAt < now) {
      return { success: false, error: 'OTP has expired' };
    }

    // Check if OTP was already used
    if (otp.usedAt) {
      return { success: false, error: 'OTP has already been used' };
    }

    // Check if max attempts exceeded
    if (otp.attempts >= maxAttempts) {
      return { success: false, error: 'Maximum OTP attempts exceeded' };
    }

    // Increment attempt count
    await this.prisma.orchestrawOtp.update({
      where: { id: otp.id },
      data: { attempts: otp.attempts + 1 },
    });

    // Validate OTP code
    if (codeHash !== otp.codeHash) {
      return { success: false, error: 'Invalid OTP code' };
    }

    // Mark OTP as used
    await this.prisma.orchestrawOtp.update({
      where: { id: otp.id },
      data: { usedAt: now },
    });

    return { success: true };
  }

  /**
   * Get unused OTP for email/purpose
   */
  async getUnusedOtp(email: string, purpose: 'EMAIL_VERIFY' | 'PASSWORD_RESET') {
    return this.prisma.orchestrawOtp.findFirst({
      where: {
        email,
        purpose,
        usedAt: null,
        expiresAt: {
          gt: new Date(),
        },
      },
      orderBy: {
        createdAt: 'desc',
      },
    });
  }

  /**
   * Check if OTP can be resent (rate limiting)
   */
  async canResendOtp(
    email: string,
    purpose: 'EMAIL_VERIFY' | 'PASSWORD_RESET',
    resendIntervalSeconds: number = 30,
  ): Promise<boolean> {
    const latestOtp = await this.getUnusedOtp(email, purpose);

    if (!latestOtp || !latestOtp.lastSentAt) {
      return true;
    }

    const timeSinceLastSent =
      (Date.now() - latestOtp.lastSentAt.getTime()) / 1000;
    return timeSinceLastSent >= resendIntervalSeconds;
  }

  /**
   * Update last sent timestamp for resend tracking
   */
  async updateLastSent(email: string, purpose: 'EMAIL_VERIFY' | 'PASSWORD_RESET') {
    const otp = await this.getUnusedOtp(email, purpose);
    if (otp) {
      await this.prisma.orchestrawOtp.update({
        where: { id: otp.id },
        data: { lastSentAt: new Date() },
      });
    }
  }

  /**
   * Invalidate all OTPs for an email/purpose
   */
  async invalidateOtps(email: string, purpose: 'EMAIL_VERIFY' | 'PASSWORD_RESET') {
    await this.prisma.orchestrawOtp.updateMany({
      where: {
        email,
        purpose,
        usedAt: null,
      },
      data: {
        usedAt: new Date(),
      },
    });
  }

  /**
   * Get OTP count for attempts limit check
   */
  async getOtpAttemptCount(email: string, purpose: 'EMAIL_VERIFY' | 'PASSWORD_RESET') {
    const otp = await this.getUnusedOtp(email, purpose);
    return otp?.attempts || 0;
  }
}
