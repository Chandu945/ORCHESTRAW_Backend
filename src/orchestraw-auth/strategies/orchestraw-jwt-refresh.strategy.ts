import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import { Request } from 'express';

@Injectable()
export class OrchestrawJwtRefreshStrategy extends PassportStrategy(
  Strategy,
  'orchestraw-jwt-refresh',
) {
  constructor(configService: ConfigService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: configService.get<string>(
        'ORCHESTRAW_JWT_REFRESH_SECRET',
        'orchestraw-refresh-secret-key',
      ),
      passReqToCallback: true,
    });
  }

  async validate(req: Request, payload: any) {
    const refreshToken = ExtractJwt.fromAuthHeaderAsBearerToken()(req);
    return {
      accountId: payload.sub,
      email: payload.email,
      refreshToken,
      type: payload.type,
    };
  }
}
