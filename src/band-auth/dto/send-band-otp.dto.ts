import { IsEmail, IsNotEmpty, IsString } from 'class-validator';

export class SendBandOtpDto {
  @IsNotEmpty()
  @IsEmail()
  email: string;
}
