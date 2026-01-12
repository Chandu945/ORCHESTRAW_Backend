import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';

@Injectable()
export class BandJwtAccessStrategy extends PassportStrategy(
  Strategy,
  'band-jwt-access',
) {
  constructor() {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: process.env.JWT_SECRET || 'band-access-secret',
    });
  }

  async validate(payload: any) {
    if (payload.type !== 'access') {
      throw new Error('Invalid token type');
    }
    return {
      bandId: payload.bandId,
      email: payload.email,
    };
  }
}
