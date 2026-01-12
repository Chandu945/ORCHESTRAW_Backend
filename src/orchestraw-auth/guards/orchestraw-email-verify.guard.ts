import {
  Injectable,
  UnauthorizedException,
  ForbiddenException,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { ExecutionContext } from '@nestjs/common';

@Injectable()
export class OrchestrawEmailVerifyGuard extends AuthGuard(
  'orchestraw-email-verify',
) {
  canActivate(context: ExecutionContext) {
    return super.canActivate(context);
  }

  handleRequest(err: any, user: any, info: any, context: ExecutionContext) {
    if (err || !user) {
      if (info?.message === 'jwt expired') {
        throw new UnauthorizedException(
          'Email verification token expired. Please request a new OTP.',
        );
      }

      if (info?.message === 'invalid token') {
        throw new UnauthorizedException(
          'Invalid or malformed email verification token.',
        );
      }

      throw new UnauthorizedException(
        'Email verification token is missing or invalid.',
      );
    }

    // 🔒 Mandatory payload checks
    if (!user.email) {
      throw new ForbiddenException(
        'Email not found in verification token.',
      );
    }

    if (!user.type || user.type !== 'email_verify') {
      throw new ForbiddenException(
        'Invalid token type. Email verification token required.',
      );
    }

    // Passport will attach this to req.user automatically
    return user;
  }
}
