import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';

@Injectable()
export class BandJwtRefreshStrategy extends PassportStrategy(
  Strategy,
  'band-jwt-refresh',
) {
  constructor() {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: process.env.JWT_REFRESH_SECRET || 'band-refresh-secret',
    });
  }

  async validate(payload: any) {
    if (payload.type !== 'refresh') {
      throw new Error('Invalid token type');
    }
    return {
      bandId: payload.bandId,
      email: payload.email,
    };
  }
}
