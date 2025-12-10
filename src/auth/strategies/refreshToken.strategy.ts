import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import type { Request } from 'express';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

type JwtPayload = {
  sub: string;
  email: string;
  role?: string;
};

@Injectable()
export class RefreshTokenStrategy extends PassportStrategy(
  Strategy,
  'jwt-refresh',
) {
  constructor(config: ConfigService) {
    const secret = config.get<string>('JWT_REFRESH_SECRET');
    if (!secret) {
      throw new Error('JWT_REFRESH_SECRET is not set');
    }

    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: secret,
      passReqToCallback: true, // <--- Important: allows us to access the raw token
    });
  }

  validate(req: Request, payload: JwtPayload) {
    const authHeader = req.get('authorization');
    const refreshToken = authHeader?.replace(/Bearer\s*/i, '').trim();
    if (!refreshToken) {
      throw new UnauthorizedException('Refresh token missing');
    }

    return { ...payload, refreshToken };
  }
}
