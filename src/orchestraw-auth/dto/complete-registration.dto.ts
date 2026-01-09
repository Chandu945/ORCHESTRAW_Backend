import {
  IsString,
  IsStrongPassword,
  Length,
  Matches,
} from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class CompleteRegistrationDto {
  @ApiProperty({
    example: 'ACME Corp',
    description: 'Display name (2-100 characters)',
  })
  @IsString()
  @Length(2, 100)
  displayName: string;

  @ApiProperty({
    example: 'John Doe',
    description: 'Contact name (2-100 characters)',
  })
  @IsString()
  @Length(2, 100)
  contactName: string;

  @ApiProperty({
    example: '9876543210',
    description: 'Phone number (10 digits)',
  })
  @IsString()
  @Matches(/^[0-9]{10}$/, { message: 'phoneNumber must be a valid 10-digit number' })
  phoneNumber: string;

  @ApiProperty({
    example: 'SecurePassword123!',
    description: 'Password (min 8 chars: 1 uppercase, 1 lowercase, 1 number, 1 symbol)',
  })
  @IsString()
  @IsStrongPassword(
    {
      minLength: 8,
      minLowercase: 1,
      minUppercase: 1,
      minNumbers: 1,
      minSymbols: 1,
    },
    {
      message:
        'Password must be at least 8 characters with 1 uppercase, 1 lowercase, 1 number, and 1 symbol',
    },
  )
  password: string;
}
