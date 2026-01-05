import { IsEmail, IsNotEmpty, IsString } from 'class-validator';

export class ForgotPasswordBandDto {
  @IsNotEmpty()
  @IsEmail()
  email: string;
}
