import { PassportStrategy } from '@nestjs/passport';
import { Strategy, VerifyCallback } from 'passport-google-oauth20';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
  constructor(config: ConfigService) {
    const clientID = config.get<string>('GOOGLE_CLIENT_ID');
    const clientSecret = config.get<string>('GOOGLE_CLIENT_SECRET');
    const callbackURL = config.get<string>('GOOGLE_CALLBACK_URL');

    if (!clientID || !clientSecret || !callbackURL) {
      throw new Error('Google OAuth env vars are not set');
    }

    super({
      clientID,
      clientSecret,
      callbackURL,
      scope: ['email', 'profile'],
    });
  }

  async validate(
    accessToken: string,
    refreshToken: string,
    profile: any,
    done: VerifyCallback,
  ) {
    const { id, name, emails, photos } = profile;

    const email = emails?.[0]?.value;
    if (!email) {
      return done(
        new UnauthorizedException('Google account does not have an email'),
        false,
      );
    }

    const userProfile = {
      email,
      firstName: name?.givenName,
      lastName: name?.familyName ?? null,
      googleId: id,
      profileImageUrl: photos?.[0]?.value ?? null,
    };

    return done(null, userProfile);
  }
}
