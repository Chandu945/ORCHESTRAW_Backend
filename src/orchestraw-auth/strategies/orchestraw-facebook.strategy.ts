import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-facebook';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class OrchestrawFacebookStrategy extends PassportStrategy(
  Strategy,
  'orchestraw-facebook',
) {
  constructor(private config: ConfigService) {
    const appID = config.get<string>('FACEBOOK_APP_ID');
    const appSecret = config.get<string>('FACEBOOK_APP_SECRET');
    const callbackURL = config.get<string>('ORCHESTRAW_FACEBOOK_CALLBACK_URL');

    if (!appID || !appSecret || !callbackURL) {
      throw new Error('Facebook OAuth env vars for orchestraw are not set');
    }

    super({
      clientID: appID,
      clientSecret: appSecret,
      callbackURL,
      profileFields: ['id', 'displayName', 'name', 'emails', 'photos'],
    });
  }

  async validate(
    accessToken: string,
    refreshToken: string,
    profile: any,
    done: any,
  ) {
    const { id, displayName, name, emails, photos } = profile;

    const email = emails?.[0]?.value;
    if (!email) {
      return done(
        new UnauthorizedException('Facebook account does not have an email'),
        false,
      );
    }

    const userProfile = {
      email,
      displayName: displayName || 'User',
      contactName:
        `${name?.givenName || ''} ${name?.familyName || ''}`.trim() ||
        displayName,
      profileImageUrl: photos?.[0]?.value ?? null,
      provider: 'FACEBOOK',
    };

    return done(null, userProfile);
  }
}
