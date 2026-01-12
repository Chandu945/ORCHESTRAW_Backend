import { IsEmail, IsNotEmpty, IsString } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class VerifyForgotPasswordOtpBandDto {
  @ApiProperty({
    description: 'Band owner email address',
    example: 'owner@band.com',
  })
  @IsNotEmpty()
  @IsEmail()
  email: string;

  @ApiProperty({
    description: 'OTP sent to email for password reset',
    example: '123456',
  })
  @IsNotEmpty()
  @IsString()
  otp: string;
}
