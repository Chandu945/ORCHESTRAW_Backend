import { IsEmail, IsNotEmpty, IsString } from 'class-validator';

export class LoginBandDto {
  @IsNotEmpty()
  @IsEmail()
  email: string;

  @IsNotEmpty()
  @IsString()
  password: string;
}
