import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  Injectable,
  NotFoundException,
  HttpException,
  HttpStatus,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import * as bcrypt from 'bcrypt';
import { PrismaService } from '../prisma/prisma.service';
import { OrchestrawOtpService } from './orchestraw-otp.service';
import { MailService } from '../mail/mail.service';
import { StartEmailVerificationDto } from './dto/start-email-verification.dto';
import { VerifyEmailOtpDto } from './dto/verify-email-otp.dto';
import { CompleteRegistrationDto } from './dto/complete-registration.dto';
import { LoginOrchestrawDto } from './dto/login-orchestraw.dto';
import { OrchestrawForgotPasswordDto } from './dto/forgot-password.dto';
import { OrchestarwResetPasswordDto } from './dto/reset-password.dto';

@Injectable()
export class OrchestrawAuthService {
  private readonly otpExpiry = 10; // minutes
  private readonly maxOtpAttempts = 5;
  private readonly otpResendInterval = 30; // seconds

  constructor(
    private prisma: PrismaService,
    private otpService: OrchestrawOtpService,
    private jwtService: JwtService,
    private configService: ConfigService,
    private mailService: MailService,
  ) { }

  /**
   * Step 1: Start Email Verification
   * Generates OTP and sends via email
   */
  async startEmailVerification(
    dto: StartEmailVerificationDto,
  ): Promise<{ message: string; expiresAt: Date }> {
    const { email } = dto;

    // Check if email is already registered
    const existingAccount = await this.prisma.orchestrawAccount.findUnique({
      where: { email },
    });

    if (existingAccount) {
      throw new ConflictException('Email is already registered');
    }

    // Check if OTP can be resent
    const canResend = await this.otpService.canResendOtp(
      email,
      'EMAIL_VERIFY',
      this.otpResendInterval,
    );

    if (!canResend) {
      throw new HttpException(
        'Please wait before requesting a new OTP',
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }

    // Create OTP
    const { code, expiresAt } = await this.otpService.createOtp(
      email,
      'EMAIL_VERIFY',
      this.otpExpiry,
    );

    // Send OTP via email
    try {
      await this.mailService.sendOtp(email, code);
    } catch (error) {
      // Delete the OTP if email sending fails
      await this.otpService.invalidateOtps(
        email,
        'EMAIL_VERIFY',
      );
      throw new BadRequestException('Failed to send OTP email');
    }

    // Update last sent timestamp
    await this.otpService.updateLastSent(
      email,
      'EMAIL_VERIFY',
    );

    return {
      message: 'OTP sent successfully to your email',
      expiresAt,
    };
  }

  /**
   * Step 2: Verify Email OTP
   * Issues email verification token upon successful verification
   */
  async verifyEmailOtp(dto: VerifyEmailOtpDto): Promise<{ verificationToken: string }> {
    const { email, otp } = dto;

    // Verify OTP
    const result = await this.otpService.verifyOtp(
      email,
      otp,
      'EMAIL_VERIFY',
      this.maxOtpAttempts,
    );

    if (!result.success) {
      if (result.error === 'Maximum OTP attempts exceeded') {
        throw new HttpException(result.error, HttpStatus.TOO_MANY_REQUESTS);
      }
      throw new BadRequestException(result.error);
    }

    // Create email verification token
    const verificationToken = this.jwtService.sign(
      {
        email,
        type: 'email_verify',
      },
      {
        secret: this.configService.get<string>(
          'ORCHESTRAW_JWT_EMAIL_VERIFY_SECRET',
          'orchestraw-email-verify-secret-key',
        ),
        expiresIn: '15m',
      },
    );

    return { verificationToken };
  }

  /**
   * Step 3: Complete Registration
   * Creates OrchestrawAccount after email verification
   */
  async completeRegistration(
    email: string,
    dto: CompleteRegistrationDto,
  ): Promise<{ message: string; accountId: string }> {
    const { displayName, contactName, phoneNumber, password } = dto;

    // 1️⃣ Email must NOT already be registered
    const existingAccount = await this.prisma.orchestrawAccount.findUnique({
      where: { email },
    });

    if (existingAccount) {
      throw new ConflictException('Email already registered');
    }

    // 2️⃣ Phone number uniqueness
    const phoneOwner = await this.prisma.orchestrawAccount.findUnique({
      where: { phoneNumber },
    });

    if (phoneOwner) {
      throw new ConflictException('Phone number already registered');
    }

    // 3️⃣ Hash password
    const passwordHash = await bcrypt.hash(password, 10);

    // 4️⃣ Create account (THIS is the registration moment)
    const account = await this.prisma.orchestrawAccount.create({
      data: {
        displayName,
        contactName,
        email,
        phoneNumber,
        passwordHash,
        emailVerified: true,
        status: 'ACTIVE',
      },
    });

    // 5️⃣ Best-effort welcome email
    this.mailService
      .sendWelcome(email, displayName)
      .catch(err => console.error('Welcome email failed', err));

    return {
      message: 'Account created successfully',
      accountId: account.id,
    };
  }


  /**
   * Login with email and password
   */
  async login(
    dto: LoginOrchestrawDto,
  ): Promise<{ accessToken: string; refreshToken: string; account: any }> {
    const { email, password } = dto;

    // Find account
    const account = await this.prisma.orchestrawAccount.findUnique({
      where: { email },
    });

    if (!account) {
      throw new UnauthorizedException('Invalid credentials');
    }

    // Check if email is verified
    if (!account.emailVerified) {
      throw new ForbiddenException('Email is not verified');
    }

    // Check account status
    if (account.status !== 'ACTIVE') {
      throw new ForbiddenException('Account is suspended');
    }

    // Verify password
    const isPasswordValid = await bcrypt.compare(password, account.passwordHash);

    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid credentials');
    }

    // Generate tokens
    const { accessToken, refreshToken } = await this.generateTokens(account.id, email);

    // Store refresh token hash
    const refreshTokenHash = await bcrypt.hash(refreshToken, 10);
    await this.prisma.orchestrawAccount.update({
      where: { id: account.id },
      data: { refreshTokenHash },
    });

    return {
      accessToken,
      refreshToken,
      account: {
        id: account.id,
        email: account.email,
        displayName: account.displayName,
        contactName: account.contactName,
        phoneNumber: account.phoneNumber,
        emailVerified: account.emailVerified,
        status: account.status,
      },
    };
  }

  /**
   * Request password reset OTP
   */
  async forgotPassword(dto: OrchestrawForgotPasswordDto): Promise<{ message: string; expiresAt: Date }> {
    const { email } = dto;

    // Check if account exists
    const account = await this.prisma.orchestrawAccount.findUnique({
      where: { email },
    });

    if (!account) {
      // Don't reveal if email exists (security)
      return {
        message: 'If email exists, OTP will be sent',
        expiresAt: new Date(Date.now() + this.otpExpiry * 60 * 1000),
      };
    }

    // Check if OTP can be resent
    const canResend = await this.otpService.canResendOtp(
      email,
      'PASSWORD_RESET',
      this.otpResendInterval,
    );

    if (!canResend) {
      throw new HttpException(
        'Please wait before requesting a new OTP',
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }

    // Create OTP
    const { code, expiresAt } = await this.otpService.createOtp(
      email,
      'PASSWORD_RESET',
      this.otpExpiry,
    );

    // Send OTP via email
    try {
      await this.mailService.sendOtp(email, code);
    } catch (error) {
      await this.otpService.invalidateOtps(
        email,
        'PASSWORD_RESET',
      );
      throw new BadRequestException('Failed to send OTP email');
    }

    // Update last sent timestamp
    await this.otpService.updateLastSent(
      email,
      'PASSWORD_RESET',
    );

    return {
      message: 'If email exists, OTP will be sent',
      expiresAt,
    };
  }

  /**
   * Reset password with OTP verification
   */
  async resetPassword(dto: OrchestarwResetPasswordDto): Promise<{ message: string }> {
    const { email, otp, newPassword } = dto;

    // Find account
    const account = await this.prisma.orchestrawAccount.findUnique({
      where: { email },
    });

    if (!account) {
      throw new NotFoundException('Account not found');
    }

    // Verify OTP
    const result = await this.otpService.verifyOtp(
      email,
      otp,
      'PASSWORD_RESET',
      this.maxOtpAttempts,
    );

    if (!result.success) {
      if (result.error === 'Maximum OTP attempts exceeded') {
        throw new HttpException(result.error, HttpStatus.TOO_MANY_REQUESTS);
      }
      throw new BadRequestException(result.error);
    }

    // Hash new password
    const passwordHash = await bcrypt.hash(newPassword, 10);

    // Update password and invalidate all refresh tokens
    await this.prisma.orchestrawAccount.update({
      where: { id: account.id },
      data: {
        passwordHash,
        refreshTokenHash: null, // Invalidate all sessions
      },
    });

    return { message: 'Password reset successfully' };
  }

  /**
   * Refresh access token
   */
  async refreshAccessToken(
    accountId: string,
    refreshToken: string,
  ): Promise<{ accessToken: string }> {
    // Find account
    const account = await this.prisma.orchestrawAccount.findUnique({
      where: { id: accountId },
    });

    if (!account || !account.refreshTokenHash) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    // Verify refresh token hash
    const isTokenValid = await bcrypt.compare(refreshToken, account.refreshTokenHash);

    if (!isTokenValid) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    // Generate new access token
    const accessToken = this.jwtService.sign(
      {
        sub: account.id,
        email: account.email,
        type: 'access',
      },
      {
        secret: this.configService.get<string>(
          'ORCHESTRAW_JWT_ACCESS_SECRET',
          'orchestraw-access-secret-key',
        ),
        expiresIn: '15m',
      },
    );

    return { accessToken };
  }

  /**
   * Handle Google OAuth Sign-in
   * If account exists, login. If not, create new account
   */
  async googleSignin(googleProfile: any): Promise<{
    accessToken: string;
    refreshToken: string;
    account: any;
  }> {
    const { email, displayName, contactName, profileImageUrl } = googleProfile;

    // Check if account already exists
    let account = await this.prisma.orchestrawAccount.findUnique({
      where: { email },
    });

    if (account) {
      // Account exists, generate tokens
      const tokens = await this.generateTokens(account.id, account.email);
      return {
        ...tokens,
        account: {
          id: account.id,
          email: account.email,
          displayName: account.displayName,
          contactName: account.contactName,
          emailVerified: account.emailVerified,
          status: account.status,
        },
      };
    }

    // Create new account
    const hashedPassword = await bcrypt.hash(
      Math.random().toString(36).slice(-12),
      10,
    ); // Random password for OAuth users

    account = await this.prisma.orchestrawAccount.create({
      data: {
        email,
        displayName: displayName || email.split('@')[0],
        contactName: contactName || displayName || email.split('@')[0],
        phoneNumber: `+auto-${Date.now()}`, // Placeholder
        passwordHash: hashedPassword,
        emailVerified: true, // OAuth emails are verified
        status: 'ACTIVE',
      },
    });

    const tokens = await this.generateTokens(account.id, account.email);
    return {
      ...tokens,
      account: {
        id: account.id,
        email: account.email,
        displayName: account.displayName,
        contactName: account.contactName,
        emailVerified: account.emailVerified,
        status: account.status,
      },
    };
  }

  /**
   * Handle Facebook OAuth Sign-in
   * If account exists, login. If not, create new account
   */
  async facebookSignin(facebookProfile: any): Promise<{
    accessToken: string;
    refreshToken: string;
    account: any;
  }> {
    const { email, displayName, contactName, profileImageUrl } =
      facebookProfile;

    // Check if account already exists
    let account = await this.prisma.orchestrawAccount.findUnique({
      where: { email },
    });

    if (account) {
      // Account exists, generate tokens
      const tokens = await this.generateTokens(account.id, account.email);
      return {
        ...tokens,
        account: {
          id: account.id,
          email: account.email,
          displayName: account.displayName,
          contactName: account.contactName,
          emailVerified: account.emailVerified,
          status: account.status,
        },
      };
    }

    // Create new account
    const hashedPassword = await bcrypt.hash(
      Math.random().toString(36).slice(-12),
      10,
    ); // Random password for OAuth users

    account = await this.prisma.orchestrawAccount.create({
      data: {
        email,
        displayName: displayName || email.split('@')[0],
        contactName: contactName || displayName || email.split('@')[0],
        phoneNumber: `+auto-${Date.now()}`, // Placeholder
        passwordHash: hashedPassword,
        emailVerified: true, // OAuth emails are verified
        status: 'ACTIVE',
      },
    });

    const tokens = await this.generateTokens(account.id, account.email);
    return {
      ...tokens,
      account: {
        id: account.id,
        email: account.email,
        displayName: account.displayName,
        contactName: account.contactName,
        emailVerified: account.emailVerified,
        status: account.status,
      },
    };
  }

  /**
   * Generate both access and refresh tokens
   */
  private async generateTokens(
    accountId: string,
    email: string,
  ): Promise<{ accessToken: string; refreshToken: string }> {
    const accessToken = this.jwtService.sign(
      {
        sub: accountId,
        email,
        type: 'access',
      },
      {
        secret: this.configService.get<string>(
          'ORCHESTRAW_JWT_ACCESS_SECRET',
          'orchestraw-access-secret-key',
        ),
        expiresIn: '15m',
      },
    );

    const refreshToken = this.jwtService.sign(
      {
        sub: accountId,
        email,
        type: 'refresh',
      },
      {
        secret: this.configService.get<string>(
          'ORCHESTRAW_JWT_REFRESH_SECRET',
          'orchestraw-refresh-secret-key',
        ),
        expiresIn: '7d',
      },
    );

    return { accessToken, refreshToken };
  }
}
