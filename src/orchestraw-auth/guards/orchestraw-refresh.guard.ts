import { Injectable, UnauthorizedException, ForbiddenException } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { ExecutionContext } from '@nestjs/common';

@Injectable()
export class OrchestrawRefreshGuard extends AuthGuard('orchestraw-jwt-refresh') {
  canActivate(context: ExecutionContext) {
    return super.canActivate(context);
  }

  handleRequest(err: any, user: any, info: any, context: ExecutionContext) {
    const request = context.switchToHttp().getRequest();

    if (err || !user) {
      if (info && info.message === 'jwt expired') {
        throw new UnauthorizedException('Refresh token expired. Please login again.');
      }
      if (info && info.message === 'invalid token') {
        throw new UnauthorizedException('Invalid or malformed refresh token.');
      }
      throw new UnauthorizedException('Refresh token is missing or invalid.');
    }

    if (!user.accountId) {
      throw new ForbiddenException('Account ID not found in refresh token.');
    }

    if (!user.email) {
      throw new ForbiddenException('Email not found in refresh token.');
    }

    if (!user.refreshToken) {
      throw new ForbiddenException('Refresh token value is missing.');
    }

    if (user.type !== 'refresh') {
      throw new ForbiddenException('Invalid token type. Expected refresh token.');
    }

    request.user = user;
    return user;
  }
}
