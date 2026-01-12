import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class OrchestrawEmailVerifyStrategy extends PassportStrategy(
  Strategy,
  'orchestraw-email-verify',
) {
  constructor(private readonly configService: ConfigService) {
    super({
      // 🔹 Reads token ONLY from:
      // Authorization: Bearer <JWT>
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),

      // 🔹 Token must NOT be expired
      ignoreExpiration: false,

      // 🔹 Secret used to verify email verification token
      secretOrKey: configService.get<string>(
        'ORCHESTRAW_JWT_EMAIL_VERIFY_SECRET',
        'orchestraw-email-verify-secret-key',
      ),
    });
  }

  // 🔹 Runs ONLY after JWT is verified successfully
  async validate(payload: any) {
    return {
      email: payload.email,
      type: payload.type, // must be 'email_verify'
    };
  }
}
