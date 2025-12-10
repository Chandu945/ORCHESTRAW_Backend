import { Injectable } from '@nestjs/common';
import { ThrottlerGuard } from '@nestjs/throttler';

@Injectable()
export class OtpThrottlerGuard extends ThrottlerGuard {
  protected async getTracker(req: Record<string, any>): Promise<string> {
    // Track by email when available (protects against IP rotation)
    if (req.body?.email) {
      return `otp:${req.body.email}`;
    }

    // Fallback to IP tracking
    return req.ips?.length ? req.ips[0] : req.ip;
  }

  protected errorMessage =
    'Too many OTP requests for this email. Please wait a minute.';
}
