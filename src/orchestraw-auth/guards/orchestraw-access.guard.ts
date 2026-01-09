import { Injectable, UnauthorizedException, ForbiddenException } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { ExecutionContext } from '@nestjs/common';

@Injectable()
export class OrchestrawAccessGuard extends AuthGuard('orchestraw-jwt-access') {
  canActivate(context: ExecutionContext) {
    return super.canActivate(context);
  }

  handleRequest(err: any, user: any, info: any, context: ExecutionContext) {
    const request = context.switchToHttp().getRequest();

    if (err || !user) {
      if (info && info.message === 'jwt expired') {
        throw new UnauthorizedException('Access token expired. Please refresh your token.');
      }
      if (info && info.message === 'invalid token') {
        throw new UnauthorizedException('Invalid or malformed access token.');
      }
      throw new UnauthorizedException('Access token is missing or invalid.');
    }

    if (!user.accountId) {
      throw new ForbiddenException('Account ID not found in token.');
    }

    if (!user.email) {
      throw new ForbiddenException('Email not found in token.');
    }

    if (user.type !== 'access') {
      throw new ForbiddenException('Invalid token type. Expected access token.');
    }

    request.user = user;
    return user;
  }
}
