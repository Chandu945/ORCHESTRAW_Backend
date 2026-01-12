import { IsEmail, IsNotEmpty, IsString } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class LoginBandDto {
  @ApiProperty({
    description: 'Band owner email address',
    example: 'owner@band.com',
  })
  @IsNotEmpty()
  @IsEmail()
  email: string;

  @ApiProperty({
    description: 'Band owner password',
    example: 'Password@123',
  })
  @IsNotEmpty()
  @IsString()
  password: string;
}
