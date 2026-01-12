import {
  Body,
  Controller,
  Post,
  UseGuards,
  Request,
  Get,
} from '@nestjs/common';
import { OrchestrawAuthService } from './orchestraw-auth.service';
import { StartEmailVerificationDto } from './dto/start-email-verification.dto';
import { VerifyEmailOtpDto } from './dto/verify-email-otp.dto';
import { CompleteRegistrationDto } from './dto/complete-registration.dto';
import { LoginOrchestrawDto } from './dto/login-orchestraw.dto';
import { OrchestrawForgotPasswordDto } from './dto/forgot-password.dto';
import { OrchestarwResetPasswordDto } from './dto/reset-password.dto';
import { OrchestrawAccessGuard } from './guards/orchestraw-access.guard';
import { OrchestrawRefreshGuard } from './guards/orchestraw-refresh.guard';
import { OrchestrawEmailVerifyGuard } from './guards/orchestraw-email-verify.guard';
import { ApiBearerAuth } from '@nestjs/swagger';

@Controller('/orchestraw-auth')
export class OrchestrawAuthController {
  constructor(private authService: OrchestrawAuthService) {}

  /**
   * Step 1: Start Email Verification
   * POST /api/v1/orchestraw-auth/start-email-verification
   * Body: { email: string }
   */
  @Post('start-email-verification')
  async startEmailVerification(
    @Body() dto: StartEmailVerificationDto,
  ) {
    return await this.authService.startEmailVerification(dto);
  }

  /**
   * Step 2: Verify Email OTP
   * POST /api/v1/orchestraw-auth/verify-email-otp
   * Body: { email: string, otp: string }
   */
  @Post('verify-email-otp')
  async verifyEmailOtp(@Body() dto: VerifyEmailOtpDto) {
    return await this.authService.verifyEmailOtp(dto);
  }

  /**
   * Step 3: Complete Registration
   * POST /api/v1/orchestraw-auth/complete-registration
   * Authorization: Bearer email_verify_jwt
   * Body: { displayName, contactName, phoneNumber, password }
   */
  // @Post('complete-registration')
  // @UseGuards(OrchestrawEmailVerifyGuard)
  // async completeRegistration(
  //   @Request() req,
  //   @Body() dto: CompleteRegistrationDto,
  // ) {
  //   const email = req.user.email;
  //   return await this.authService.completeRegistration(email, dto);
  // }
  @ApiBearerAuth('email-verify-token')
   @Post('complete-registration')
  @UseGuards(OrchestrawEmailVerifyGuard)
  async completeRegistration(
    @Request() req,
    @Body() dto: CompleteRegistrationDto,
  ) {
    // 🔹 Comes from validate() in strategy
    const email = req.user.email;

    return this.authService.completeRegistration(email, dto);
  }

  /**
   * Login
   * POST /api/v1/orchestraw-auth/login
   * Body: { email: string, password: string }
   */
  @Post('login')
  async login(@Body() dto: LoginOrchestrawDto) {
    return await this.authService.login(dto);
  }

  /**
   * Forgot Password - Request OTP
   * POST /api/v1/orchestraw-auth/forgot-password
   * Body: { email: string }
   */
  @Post('forgot-password')
  async forgotPassword(@Body() dto: OrchestrawForgotPasswordDto) {
    return await this.authService.forgotPassword(dto);
  }

  /**
   * Reset Password - With OTP Verification
   * POST /api/v1/orchestraw-auth/reset-password
   * Body: { email: string, otp: string, newPassword: string }
   */
  @Post('reset-password')
  async resetPassword(@Body() dto: OrchestarwResetPasswordDto) {
    return await this.authService.resetPassword(dto);
  }

  /**
   * Refresh Access Token
   * POST /api/v1/orchestraw-auth/refresh
   * Authorization: Bearer refresh_token
   */
  @Post('refresh')
  @UseGuards(OrchestrawRefreshGuard)
  async refresh(@Request() req) {
    const { accountId, refreshToken } = req.user;
    return await this.authService.refreshAccessToken(accountId, refreshToken);
  }

  /**
   * Get Current Account (Protected Route)
   * GET /api/v1/orchestraw-auth/me
   * Authorization: Bearer access_token
   */
  @Get('me')
  @UseGuards(OrchestrawAccessGuard)
  async getCurrentAccount(@Request() req) {
    return {
      accountId: req.user.accountId,
      email: req.user.email,
    };
  }
}
