import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { UserRole, AuthProvider } from '@prisma/client';
import * as bcrypt from 'bcrypt';

@Injectable()
export class SeedService {
  private readonly logger = new Logger(SeedService.name);

  constructor(private readonly prisma: PrismaService) {}

  async seedAdmins() {
    await this.createAdminIfNotExists({
      email: process.env.ADMIN_EMAIL!,
      password: process.env.ADMIN_PASSWORD!,
      role: UserRole.ADMIN,
      firstName: 'Admin',
      lastName: 'User',
    });

    await this.createAdminIfNotExists({
      email: process.env.SUPER_ADMIN_EMAIL!,
      password: process.env.SUPER_ADMIN_PASSWORD!,
      role: UserRole.SUPER_ADMIN,
      firstName: 'Super',
      lastName: 'Admin',
    });
  }

  private async createAdminIfNotExists(data: {
    email: string;
    password: string;
    role: UserRole;
    firstName: string;
    lastName: string;
  }) {
    const existingUser = await this.prisma.user.findUnique({
      where: { email: data.email },
    });

    if (existingUser) {
      this.logger.log(
        `${data.role} already exists → ${data.email}`,
      );
      return;
    }

    const passwordHash = await bcrypt.hash(data.password, 10);

    await this.prisma.user.create({
      data: {
        email: data.email,
        passwordHash,
        firstName: data.firstName,
        lastName: data.lastName,
        role: data.role,
        provider: AuthProvider.LOCAL,
        isEmailVerified: true,
      },
    });

    this.logger.log(
      `${data.role} created → ${data.email}`,
    );
  }
}
