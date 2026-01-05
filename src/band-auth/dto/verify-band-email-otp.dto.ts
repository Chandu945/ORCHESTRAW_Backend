import { IsEmail, IsNotEmpty, IsString } from 'class-validator';

export class VerifyBandEmailOtpDto {
  @IsNotEmpty()
  @IsEmail()
  email: string;

  @IsNotEmpty()
  @IsString()
  otp: string;
}
