import {
  Injectable,
  BadRequestException,
  ConflictException,
  UnauthorizedException,
  ForbiddenException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '../prisma/prisma.service';
import { MailService } from '../mail/mail.service';
import { BandOtpService } from '../band-otp/band-otp.service';
import { BandOtpPurpose } from '@prisma/client';
import * as bcrypt from 'bcrypt';
import {
  RegisterBandDto,
  SendBandOtpDto,
  VerifyBandEmailOtpDto,
  LoginBandDto,
  ForgotPasswordBandDto,
  VerifyForgotPasswordOtpBandDto,
  ResetPasswordBandDto,
} from './dto';

@Injectable()
export class BandAuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
    private readonly mailService: MailService,
    private readonly bandOtpService: BandOtpService,
  ) {}

  /**
   * Send OTP for email verification (during registration)
   */
  async sendEmailVerificationOtp(dto: SendBandOtpDto): Promise<{
    message: string;
  }> {
    const { email } = dto;

    // Check if email already registered
    const existingBand = await this.prisma.bandAccount.findUnique({
      where: { email },
    });

    if (existingBand) {
      throw new ConflictException(
        'Email already registered. Please use a different email.',
      );
    }

    // Check if there's a pending verification for this email
    let bandAccount = await this.prisma.bandAccount.findFirst({
      where: {
        email,
        emailVerified: false,
      },
    });

    // If no pending account, create one
    if (!bandAccount) {
      bandAccount = await this.prisma.bandAccount.create({
        data: {
          email,
          bandName: 'Pending',
          ownerName: 'Pending',
          phoneNumber: 'pending-' + Date.now().toString(),
          passwordHash: 'pending',
        },
      });
    }

    // Check if OTP can be resent
    const canResend = await this.bandOtpService.canResendOtp(
      bandAccount.id,
      BandOtpPurpose.EMAIL_VERIFY,
    );

    if (!canResend) {
      const waitTime = await this.bandOtpService.getResendWaitTime(
        bandAccount.id,
        BandOtpPurpose.EMAIL_VERIFY,
      );
      throw new BadRequestException(
        `Please wait ${waitTime} minute(s) before requesting a new OTP`,
      );
    }

    // Generate and store OTP
    const otp = await this.bandOtpService.generateAndStoreOtp(
      bandAccount.id,
      BandOtpPurpose.EMAIL_VERIFY,
    );

    // Send OTP via email
    await this.mailService.sendBandOtpEmail(email, otp);

    return {
      message: 'OTP sent successfully.',
    };
  }

  /**
   * Verify email OTP
   */
  async verifyEmailOtp(dto: VerifyBandEmailOtpDto): Promise<{
    message: string;
  }> {
    const { email, otp } = dto;

    const bandAccount = await this.prisma.bandAccount.findUnique({
      where: { email },
    });

    if (!bandAccount) {
      throw new BadRequestException('Email not found');
    }

    // Verify OTP
    await this.bandOtpService.verifyOtp(
      bandAccount.id,
      otp,
      BandOtpPurpose.EMAIL_VERIFY,
    );

    // Mark email as verified
    await this.prisma.bandAccount.update({
      where: { id: bandAccount.id },
      data: { emailVerified: true },
    });

    return {
      message: 'Email verified successfully.',
    };
  }

  /**
   * Register a band account
   */
  async register(dto: RegisterBandDto): Promise<{ message: string }> {
  const { email, phoneNumber, password, bandName, ownerName } = dto;

  const bandAccount = await this.prisma.bandAccount.findUnique({
    where: { email },
  });

  if (!bandAccount) {
    throw new BadRequestException(
      'Email not verified. Please verify your email first.',
    );
  }

  // ❌ Email exists but not verified
  if (!bandAccount.emailVerified) {
    throw new ForbiddenException(
      'Email not verified. Please verify your email first.',
    );
  }

  // ❌ Already fully registered
  if (bandAccount.status === 'ACTIVE') {
    throw new ConflictException('Email already registered');
  }

  // ❌ Phone already used by another ACTIVE band
  const phoneOwner = await this.prisma.bandAccount.findUnique({
    where: { phoneNumber },
  });

  if (phoneOwner && phoneOwner.id !== bandAccount.id) {
    throw new ConflictException('Phone number already registered');
  }

  const passwordHash = await bcrypt.hash(password, 10);

  await this.prisma.bandAccount.update({
    where: { id: bandAccount.id },
    data: {
      bandName,
      ownerName,
      phoneNumber,
      passwordHash,
      status: 'ACTIVE',
    },
  });

  return {
    message: 'Band registered successfully',
  };
}

  /**
   * Login band account
   */
  async login(
    dto: LoginBandDto,
  ): Promise<{
    accessToken: string;
    refreshToken: string;
    band: {
      id: string;
      bandName: string;
      status: string;
    };
  }> {
    const { email, password } = dto;

    // Find band account
    const bandAccount = await this.prisma.bandAccount.findUnique({
      where: { email },
    });

    if (!bandAccount) {
      throw new UnauthorizedException('Invalid email or password');
    }

    // Check if email is verified
    if (!bandAccount.emailVerified) {
      throw new ForbiddenException(
        'Email not verified. Please verify your email.',
      );
    }

    // Check if account is active
    if (bandAccount.status !== 'ACTIVE') {
      throw new ForbiddenException(
        `Account is ${bandAccount.status.toLowerCase()}. Please contact support.`,
      );
    }

    // Verify password
    const isPasswordValid = await bcrypt.compare(
      password,
      bandAccount.passwordHash,
    );

    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid email or password');
    }

    // Generate tokens
    const accessToken = this.jwtService.sign(
      {
        bandId: bandAccount.id,
        email: bandAccount.email,
        type: 'access',
      },
      {
        secret: process.env.JWT_SECRET || 'band-access-secret',
        expiresIn: '15m',
      },
    );

    const refreshToken = this.jwtService.sign(
      {
        bandId: bandAccount.id,
        email: bandAccount.email,
        type: 'refresh',
      },
      {
        secret: process.env.JWT_REFRESH_SECRET || 'band-refresh-secret',
        expiresIn: '7d',
      },
    );

    // Hash and store refresh token
    const refreshTokenHash = await bcrypt.hash(refreshToken, 10);
    await this.prisma.bandAccount.update({
      where: { id: bandAccount.id },
      data: { refreshTokenHash },
    });

    return {
      accessToken,
      refreshToken,
      band: {
        id: bandAccount.id,
        bandName: bandAccount.bandName,
        status: bandAccount.status,
      },
    };
  }

  /**
   * Send forgot password OTP
   */
  async sendForgotPasswordOtp(dto: ForgotPasswordBandDto): Promise<{
    message: string;
  }> {
    const { email } = dto;

    const bandAccount = await this.prisma.bandAccount.findUnique({
      where: { email },
    });

    if (!bandAccount) {
      throw new BadRequestException('Email not found');
    }

    // Check if OTP can be resent
    const canResend = await this.bandOtpService.canResendOtp(
      bandAccount.id,
      BandOtpPurpose.PASSWORD_RESET,
    );

    if (!canResend) {
      const waitTime = await this.bandOtpService.getResendWaitTime(
        bandAccount.id,
        BandOtpPurpose.PASSWORD_RESET,
      );
      throw new BadRequestException(
        `Please wait ${waitTime} minute(s) before requesting a new OTP`,
      );
    }

    // Generate and store OTP
    const otp = await this.bandOtpService.generateAndStoreOtp(
      bandAccount.id,
      BandOtpPurpose.PASSWORD_RESET,
    );

    // Send OTP via email
    await this.mailService.sendBandOtpEmail(email, otp);

    return {
      message: 'OTP sent successfully.',
    };
  }

  /**
   * Verify forgot password OTP
   */
  async verifyForgotPasswordOtp(
    dto: VerifyForgotPasswordOtpBandDto,
  ): Promise<{
    message: string;
  }> {
    const { email, otp } = dto;

    const bandAccount = await this.prisma.bandAccount.findUnique({
      where: { email },
    });

    if (!bandAccount) {
      throw new BadRequestException('Email not found');
    }

    // Verify OTP
    await this.bandOtpService.verifyOtp(
      bandAccount.id,
      otp,
      BandOtpPurpose.PASSWORD_RESET,
    );

    return {
      message: 'OTP verified successfully.',
    };
  }

  /**
   * Reset password
   */
  async resetPassword(dto: ResetPasswordBandDto): Promise<{
    message: string;
  }> {
    const { email, newPassword } = dto;

    const bandAccount = await this.prisma.bandAccount.findUnique({
      where: { email },
    });

    if (!bandAccount) {
      throw new BadRequestException('Email not found');
    }

    // Check if password reset OTP is verified
    const lastOtp = await this.prisma.bandOtp.findFirst({
      where: {
        bandAccountId: bandAccount.id,
        purpose: BandOtpPurpose.PASSWORD_RESET,
        usedAt: { not: null },
      },
      orderBy: {
        usedAt: 'desc',
      },
    });

    if (!lastOtp) {
      throw new BadRequestException(
        'Please verify the OTP first before resetting password',
      );
    }

    // Check if OTP is fresh (used within last 10 minutes)
    const otpAgeMinutes =
      (Date.now() - (lastOtp.usedAt?.getTime() || 0)) / (1000 * 60);
    if (otpAgeMinutes > 10) {
      throw new BadRequestException('OTP verification expired. Please retry.');
    }

    // Hash new password
    const passwordHash = await bcrypt.hash(newPassword, 10);

    // Update password and invalidate refresh token
    await this.prisma.bandAccount.update({
      where: { id: bandAccount.id },
      data: {
        passwordHash,
        refreshTokenHash: null,
      },
    });

    return {
      message: 'Password reset successfully.',
    };
  }

  /**
   * Refresh access token
   */
  async refreshAccessToken(bandId: string): Promise<{
    accessToken: string;
  }> {
    const bandAccount = await this.prisma.bandAccount.findUnique({
      where: { id: bandId },
    });

    if (!bandAccount) {
      throw new UnauthorizedException('Band not found');
    }

    // Generate new access token
    const accessToken = this.jwtService.sign(
      {
        bandId: bandAccount.id,
        email: bandAccount.email,
        type: 'access',
      },
      {
        secret: process.env.JWT_SECRET || 'band-access-secret',
        expiresIn: '15m',
      },
    );

    return {
      accessToken,
    };
  }
}
