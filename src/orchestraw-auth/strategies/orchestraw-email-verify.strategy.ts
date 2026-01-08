import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class OrchestrawEmailVerifyStrategy extends PassportStrategy(
  Strategy,
  'orchestraw-email-verify',
) {
  constructor(configService: ConfigService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: configService.get<string>(
        'ORCHESTRAW_JWT_EMAIL_VERIFY_SECRET',
        'orchestraw-email-verify-secret-key',
      ),
    });
  }

  async validate(payload: any) {
    return {
      email: payload.email,
      type: payload.type,
    };
  }
}
