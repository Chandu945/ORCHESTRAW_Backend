import { IsEmail, IsNotEmpty, IsString, MinLength, Matches } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class RegisterBandDto {
  @ApiProperty({
    description: 'Band name',
    example: 'The Beatles',
  })
  @IsNotEmpty()
  @IsString()
  bandName: string;

  @ApiProperty({
    description: 'Band owner name',
    example: 'John Lennon',
  })
  @IsNotEmpty()
  @IsString()
  ownerName: string;

  @ApiProperty({
    description: 'Band owner email',
    example: 'owner@band.com',
  })
  @IsNotEmpty()
  @IsEmail()
  email: string;

  @ApiProperty({
    description: 'Band owner phone number (10 digits)',
    example: '9876543210',
  })
  @IsNotEmpty()
  @IsString()
  @Matches(/^[0-9]{10}$/, {
    message: 'Phone number must be exactly 10 digits',
  })
  phoneNumber: string;

  @ApiProperty({
    description: 'Password (min 8 chars, 1 uppercase, 1 lowercase, 1 number, 1 special char)',
    example: 'Password@123',
  })
  @IsNotEmpty()
  @IsString()
  @MinLength(8, {
    message: 'Password must be at least 8 characters long',
  })
  @Matches(
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$/,
    {
      message:
        'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character',
    },
  )
  password: string;
}
