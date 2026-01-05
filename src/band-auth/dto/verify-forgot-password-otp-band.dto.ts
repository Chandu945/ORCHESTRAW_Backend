import { IsEmail, IsNotEmpty, IsString } from 'class-validator';

export class VerifyForgotPasswordOtpBandDto {
  @IsNotEmpty()
  @IsEmail()
  email: string;

  @IsNotEmpty()
  @IsString()
  otp: string;
}
