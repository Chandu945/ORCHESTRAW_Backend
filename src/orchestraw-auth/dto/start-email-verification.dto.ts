import { IsEmail } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class StartEmailVerificationDto {
  @ApiProperty({
    example: 'user@example.com',
    description: 'User email address to verify',
  })
  @IsEmail()
  email: string;
}
