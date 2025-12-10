import {
  IsEmail,
  IsNotEmpty,
  IsString,
  Length,
  MinLength,
} from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class ResetPasswordDto {
  @ApiProperty({ example: 'user@example.com' })
  @IsNotEmpty()
  @IsEmail()
  email: string;

  // @ApiProperty({
  //   example: '123456',
  //   description: '6-digit OTP sent for password reset',
  // })
  // @IsNotEmpty()
  // @IsString()
  // @Length(6, 6)
  // otp: string;
  
  resetToken: string;

  @ApiProperty({
    example: 'NewPassword@123',
    description: 'The new password to set (minimum 6 characters)',
  })
  @IsNotEmpty()
  @IsString()
  @MinLength(6)
  newPassword: string;
}
