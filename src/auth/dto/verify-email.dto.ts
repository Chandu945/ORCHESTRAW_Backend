import { IsEmail, IsNotEmpty, IsString, Length } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class VerifyEmailDto {
  @ApiProperty({
    example: 'user@example.com',
    description: 'Email address used for signup',
  })
  @IsNotEmpty()
  @IsEmail({}, { message: 'Invalid email format.' })
  email: string;

  @ApiProperty({
    example: '123456',
    description: '6-digit OTP sent to the user email',
  })
  @IsNotEmpty()
  @IsString()
  @Length(6, 6)
  otp: string;
}
