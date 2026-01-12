import { IsEmail } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class OrchestrawForgotPasswordDto {
  @ApiProperty({
    example: 'user@example.com',
    description: 'User email address',
  })
  @IsEmail()
  email: string;
}
