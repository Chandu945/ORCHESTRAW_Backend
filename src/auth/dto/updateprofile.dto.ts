// src/user-profile/dto/update-profile.dto.ts

import {
  IsNotEmpty,
  IsOptional,
  IsString,
  MinLength,
  MaxLength,
  Matches,
  ValidateNested,
} from 'class-validator';
import { Type } from 'class-transformer';
import { ApiProperty } from '@nestjs/swagger';

export class UpdateProfileDto {
  @ApiProperty({
    example: 'Chandrasekhar',
    description: 'First name of the user',
  })
  @IsString()
  @IsNotEmpty()
  @MinLength(2)
  @MaxLength(50)
  firstName: string;

  @ApiProperty({
    example: 'Reddy',
    description: 'Last name of the user',
  })
  @IsString()
  @IsNotEmpty()
  @MinLength(2)
  @MaxLength(50)
  lastName: string;

  @ApiProperty({
    example: '9550950825',
    description: 'User phone number (10 digit, India)',
  })
  @IsString()
  @IsNotEmpty()
  @Matches(/^[6-9]\d{9}$/, {
    message: 'Phone number must be a valid 10 digit Indian mobile number',
  })
  phoneNumber: string;

}
