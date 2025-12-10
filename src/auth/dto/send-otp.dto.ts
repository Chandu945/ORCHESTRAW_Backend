import { IsEmail, IsNotEmpty } from 'class-validator';

export class SendOtpDto {
  @IsEmail({}, { message: 'Invalid email format.' })
  @IsNotEmpty()
  email: string;
}