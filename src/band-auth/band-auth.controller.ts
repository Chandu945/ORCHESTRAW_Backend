import {
  Controller,
  Post,
  Body,
  HttpCode,
  HttpStatus,
  UseGuards,
  Get,
} from '@nestjs/common';
import { BandAuthService } from './band-auth.service';
import {
  RegisterBandDto,
  SendBandOtpDto,
  VerifyBandEmailOtpDto,
  LoginBandDto,
  ForgotPasswordBandDto,
  VerifyForgotPasswordOtpBandDto,
  ResetPasswordBandDto,
} from './dto';
import { BandAccessGuard } from './guards/band-access.guard';
import { GetBandUser } from './decorators/get-band-user.decorator';

@Controller('band-auth')
export class BandAuthController {
  constructor(private readonly bandAuthService: BandAuthService) {}

  /**
   * Send email verification OTP
   */
  @Post('send-email-otp')
  @HttpCode(HttpStatus.OK)
  async sendEmailOtp(@Body() dto: SendBandOtpDto) {
    return this.bandAuthService.sendEmailVerificationOtp(dto);
  }

  /**
   * Verify email OTP
   */
  @Post('verify-email-otp')
  @HttpCode(HttpStatus.OK)
  async verifyEmailOtp(@Body() dto: VerifyBandEmailOtpDto) {
    return this.bandAuthService.verifyEmailOtp(dto);
  }

  /**
   * Register band account
   */
  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  async register(@Body() dto: RegisterBandDto) {
    return this.bandAuthService.register(dto);
  }

  /**
   * Login band account
   */
  @Post('login')
  @HttpCode(HttpStatus.OK)
  async login(@Body() dto: LoginBandDto) {
    return this.bandAuthService.login(dto);
  }

  /**
   * Send forgot password OTP
   */
  @Post('forgot-password-otp')
  @HttpCode(HttpStatus.OK)
  async sendForgotPasswordOtp(@Body() dto: ForgotPasswordBandDto) {
    return this.bandAuthService.sendForgotPasswordOtp(dto);
  }

  /**
   * Verify forgot password OTP
   */
  @Post('forgot-password-verify-otp')
  @HttpCode(HttpStatus.OK)
  async verifyForgotPasswordOtp(@Body() dto: VerifyForgotPasswordOtpBandDto) {
    return this.bandAuthService.verifyForgotPasswordOtp(dto);
  }

  /**
   * Reset password
   */
  @Post('reset-password')
  @HttpCode(HttpStatus.OK)
  async resetPassword(@Body() dto: ResetPasswordBandDto) {
    return this.bandAuthService.resetPassword(dto);
  }

  /**
   * Refresh access token
   */
  @Get('refresh')
  @UseGuards(BandAccessGuard)
  @HttpCode(HttpStatus.OK)
  async refreshAccessToken(@GetBandUser('bandId') bandId: string) {
    return this.bandAuthService.refreshAccessToken(bandId);
  }
}
