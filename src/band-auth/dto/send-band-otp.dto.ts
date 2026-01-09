import { IsEmail, IsNotEmpty, IsString } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class SendBandOtpDto {
  @ApiProperty({
    description: 'Band owner email address',
    example: 'owner@band.com',
  })
  @IsNotEmpty()
  @IsEmail()
  email: string;
}
