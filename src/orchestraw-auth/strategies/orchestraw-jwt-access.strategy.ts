import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class OrchestrawJwtAccessStrategy extends PassportStrategy(
  Strategy,
  'orchestraw-jwt-access',
) {
  constructor(configService: ConfigService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: configService.get<string>(
        'ORCHESTRAW_JWT_ACCESS_SECRET',
        'orchestraw-access-secret-key',
      ),
    });
  }

  async validate(payload: any) {
    return {
      accountId: payload.sub,
      email: payload.email,
      type: payload.type,
    };
  }
}
