import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-google-oauth20';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class OrchestrawGoogleStrategy extends PassportStrategy(
  Strategy,
  'orchestraw-google',
) {
  constructor(private config: ConfigService) {
    const clientID = config.get<string>('GOOGLE_CLIENT_ID');
    const clientSecret = config.get<string>('GOOGLE_CLIENT_SECRET');
    const callbackURL = config.get<string>('GOOGLE_CALLBACK_URL');

    if (!clientID || !clientSecret || !callbackURL) {
      throw new Error('Google OAuth env vars for orchestraw are not set');
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
    done: any,
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
      displayName: name?.givenName || 'User',
      contactName: `${name?.givenName || ''} ${name?.familyName || ''}`.trim(),
      profileImageUrl: photos?.[0]?.value ?? null,
      provider: 'GOOGLE',
    };

    return done(null, userProfile);
  }
}
