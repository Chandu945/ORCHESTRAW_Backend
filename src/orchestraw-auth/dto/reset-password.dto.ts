import { IsEmail, IsString, IsStrongPassword, Length } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class ResetPasswordDto {
  @ApiProperty({
    example: 'user@example.com',
    description: 'User email address',
  })
  @IsEmail()
  email: string;

  @ApiProperty({
    example: '123456',
    description: 'OTP sent to email (6 digits)',
  })
  @IsString()
  @Length(6, 6)
  otp: string;

  @ApiProperty({
    example: 'NewSecurePassword123!',
    description: 'New password (min 8 chars: 1 uppercase, 1 lowercase, 1 number, 1 symbol)',
  })
  @IsString()
  @IsStrongPassword(
    {
      minLength: 8,
      minLowercase: 1,
      minUppercase: 1,
      minNumbers: 1,
      minSymbols: 1,
    },
    {
      message:
        'Password must be at least 8 characters with 1 uppercase, 1 lowercase, 1 number, and 1 symbol',
    },
  )
  newPassword: string;
}
