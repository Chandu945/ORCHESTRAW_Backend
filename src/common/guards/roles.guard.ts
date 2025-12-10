import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { UserRole } from '@prisma/client'; // UPDATED ENUM
import { ROLES_KEY } from '../decorators/roles.decorator';

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    // 1. Get roles defined on the route
    const requiredRoles = this.reflector.getAllAndOverride<UserRole[]>(
      ROLES_KEY,
      [context.getHandler(), context.getClass()],
    );

    // 2. If no roles required → allow access
    if (!requiredRoles) {
      return true;
    }

    // 3. Extract authenticated user
    const { user } = context.switchToHttp().getRequest();

    // 4. Validate role
    return requiredRoles.some((role) => user.role === role);
  }
}
