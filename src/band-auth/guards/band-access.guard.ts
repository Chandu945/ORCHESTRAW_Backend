import { Injectable, UnauthorizedException } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class BandAccessGuard extends AuthGuard('band-jwt-access') {
  handleRequest(err: any, user: any, info: any) {
    if (err || !user) {
      throw (
        err ||
        new UnauthorizedException('Invalid or expired access token')
      );
    }
    return user;
  }
}
