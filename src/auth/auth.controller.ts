import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  Req,
  Res,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignupDto } from './dto/signup.dto';
import { VerifyEmailDto } from './dto/verify-email.dto';
3;
import { LoginDto } from './dto/login.dto';
import { AccessTokenGuard } from '../common/guards/accessToken.guard';
import { RefreshTokenGuard } from '../common/guards/refreshToken.guard';
import type { Request } from 'express';
import { AuthGuard } from '@nestjs/passport';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { SkipThrottle, Throttle } from '@nestjs/throttler';
import { LoginThrottlerGuard } from '../common/guards/throttler/login-throttler.guard';
import { OtpThrottlerGuard } from '../common/guards/throttler/otp-throttler.guard';
import { SendOtpDto } from './dto/send-otp.dto';
import { VerifyResetOtpDto } from './dto/reset-otpverify.dto';

type AuthenticatedRequest = Request & {
  user?: {
    sub?: string;
    refreshToken?: string;
  };
};

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) { }

  @Post('register')
  // @Throttle({ medium: { limit: 10, ttl: 60000 } }) // 10/min → prevent mass fake signups
  async signup(@Body() signupDto: SignupDto) {
    return this.authService.signup(signupDto);
  }

  @UseGuards(OtpThrottlerGuard)
  // @Throttle({ short: { limit: 3, ttl: 60000 } }) // strict → 3 OTPs/min/email
  @Post('send-otp')
  async sendOtp(@Body() dto: SendOtpDto) {
    return this.authService.sendOtp(dto);
  }

  //email verify
  @UseGuards(LoginThrottlerGuard)
  // @Throttle({ short: { limit: 5, ttl: 60000 } }) // allow 5 mistakes, block guessing
  @Post('verify-email')
  async verifyEmail(@Body() dto: VerifyEmailDto) {
    return this.authService.verifyEmail(dto);
  }


  // LOGIN
  @UseGuards(LoginThrottlerGuard)
  // @Throttle({ short: { limit: 3, ttl: 60000 } }) // prevent brute force logins
  @Post('login')
  @HttpCode(HttpStatus.OK)
  async login(@Body() dto: LoginDto) {
    return this.authService.login(dto);
  }

  // LOGOUT
  @UseGuards(AccessTokenGuard)
  // @Throttle({ long: {} }) // logout is not sensitive → relaxed
  @Post('logout')
  logout(@Req() req: AuthenticatedRequest) {
    const userId = req.user?.sub;
    if (!userId) throw new UnauthorizedException('User payload missing');
    return this.authService.logout(userId);
  }


  // REFRESH TOKENS
  @UseGuards(RefreshTokenGuard)
  // @Throttle({ medium: { limit: 20, ttl: 30000 } }) // limit refresh abuse
  @Post('refresh')
  refreshTokens(@Req() req: AuthenticatedRequest) {
    if (!req.user?.sub || !req.user?.refreshToken) {
      throw new UnauthorizedException('Refresh token payload missing');
    }
    return this.authService.refreshTokens(req.user.sub, req.user.refreshToken);
  }


  // --- GOOGLE ONLY (Facebook Removed) ---
  @Get('google')
  @UseGuards(AuthGuard('google'))
  // @Throttle({ long: {} }) // redirect-only → safe
  googleAuth() { }

  @Get('google/callback')
  @UseGuards(AuthGuard('google'))
  // @Throttle({ medium: { limit: 20, ttl: 30000 } }) // prevent callback flooding
  async googleAuthRedirect(@Req() req, @Res() res) {
    const tokens = await this.authService.googleOAuthLogin(req.user);
    const redirectUrl = `${process.env.FRONTEND_SOCIAL_SUCCESS_URL}?access_token=${tokens.access_token}&refresh_token=${tokens.refresh_token}`;
    return res.redirect(redirectUrl);
  }


  // --- FORGOT PASSWORD ---
  @UseGuards(OtpThrottlerGuard)
  // @Throttle({ short: { limit: 3, ttl: 60000 } }) // strict: prevent OTP spam
  @Post('forgot-password')
  async forgotPassword(@Body() dto: ForgotPasswordDto) {
    return this.authService.forgotPassword(dto);
  }

  //verify otp reset
  // @Throttle({ short: { limit: 5, ttl: 60000 } }) // allow 5 mistakes
  @Post('verify-reset-otp')
  verifyResetOtp(@Body() dto: VerifyResetOtpDto) {
    return this.authService.verifyPasswordResetOtp(dto);
  }

  //reset password
  // @Throttle({ medium: { limit: 10, ttl: 60000 } }) // moderately protected
  @Post('reset-password')
  async resetPassword(@Body() dto: ResetPasswordDto) {
    return this.authService.resetPassword(dto);
  }
}
