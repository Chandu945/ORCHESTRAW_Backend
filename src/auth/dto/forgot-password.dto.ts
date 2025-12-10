import { IsEmail, IsNotEmpty } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class ForgotPasswordDto {
  @ApiProperty({
    example: 'user@example.com',
    description: 'The registered email address',
  })
  @IsNotEmpty()
  @IsEmail()
  email: string;
}
