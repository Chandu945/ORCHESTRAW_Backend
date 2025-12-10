// import { Controller, Get, Post, Body, Patch, Param, Delete } from '@nestjs/common';
// import { AdminService } from './admin.service';
// import { CreateAdminDto } from './dto/create-admin.dto';
// import { UpdateAdminDto } from './dto/update-admin.dto';

// @Controller('admin')
// export class AdminController {
//   constructor(private readonly adminService: AdminService) {}

//   @Post()
//   create(@Body() createAdminDto: CreateAdminDto) {
//     return this.adminService.create(createAdminDto);
//   }

//   @Get()
//   findAll() {
//     return this.adminService.findAll();
//   }

//   @Get(':id')
//   findOne(@Param('id') id: string) {
//     return this.adminService.findOne(+id);
//   }

//   @Patch(':id')
//   update(@Param('id') id: string, @Body() updateAdminDto: UpdateAdminDto) {
//     return this.adminService.update(+id, updateAdminDto);
//   }

//   @Delete(':id')
//   remove(@Param('id') id: string) {
//     return this.adminService.remove(+id);
//   }
// }

import { Controller, Get, UseGuards } from '@nestjs/common';
import { AdminService } from './admin.service';
import { AccessTokenGuard } from '../common/guards/accessToken.guard';
import { RolesGuard } from '../common/guards/roles.guard';
import { Roles } from '../common/decorators/roles.decorator';
import { UserRole } from '@prisma/client';

@Controller('admin')
export class AdminController {
  constructor(private readonly adminService: AdminService) {}

  @UseGuards(AccessTokenGuard, RolesGuard) // 1. Check JWT, 2. Check Role
  @Roles(UserRole.ADMIN) // Only ADMIN can access routes in this controller
  @Get()
  getAdminData() {
    return { message: 'This is top secret admin data' };
  }
}