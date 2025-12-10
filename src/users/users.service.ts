import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { Prisma } from '@prisma/client';

@Injectable()
export class UsersService {
  constructor(private prisma: PrismaService) {}

  // CREATE USER
  async create(data: Prisma.UserCreateInput) {
    return this.prisma.user.create({
      data,
    });
  }

  // FIND USER BY EMAIL
  async findByEmail(email: string) {
    return this.prisma.user.findUnique({
      where: { email },
    });
  }
  
  // FIND USER BY PHONE
  async findByPhone(phoneNumber: string) {
  return this.prisma.user.findUnique({
    where: { phoneNumber },
    });
  }

  // UPDATE USER BY ID
  async update(id: string, data: Prisma.UserUpdateInput) {
    return this.prisma.user.update({
      where: { id },
      data,
    });
  }
}
