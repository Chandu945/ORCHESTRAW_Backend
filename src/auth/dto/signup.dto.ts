import {
  IsEmail,
  IsNotEmpty,
  IsOptional,
  IsString,
  Matches,
  MinLength,
} from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class SignupDto {
  @ApiProperty({
    example: 'John',
    description: 'First name of the user',
    minLength: 2,
  })
  @IsNotEmpty({message:"First name is required."})
  @IsString()
  @MinLength(2,{message:"First name must contain only letters and be at least 2 characters long."})
  @Matches(/^[A-Za-z]+$/, {message:"Invalid First name: only alphabetic characters are permitted."})
  firstName: string;

  @ApiPropertyOptional({
    example: 'Doe',
    description: 'Last name of the user (optional)',
    minLength: 2,
  })
  @IsNotEmpty({message:"Last name is required."})
  @IsString()
  @MinLength(2, {message:"Last name must contain only letters and be at least 2 characters long."})
  @Matches(/^[A-Za-z]+$/, {message:"Invalid Last name: only alphabetic characters are permitted."})
  lastName?: string;

  @ApiProperty({
    example: 'user@example.com',
    description: 'Valid email address of the user',
  })
  @IsNotEmpty({message:"Please provide your email address to proceed."})
  @IsEmail({},{message:"Please Enter Valid Email"})
  email: string;

  @ApiPropertyOptional({
    example: '+91 9876543210',
    description: 'Phone number of the user (optional)',
  })
  @IsNotEmpty({message:"Phone number is required."})
  @IsString()
  @Matches(/^(\+91)?[6-9]\d{9}$/, {message: "Must be a valid phone number (use +91XXXXXXXXXX or 10-digit format)."})
  phoneNumber: string;

  @ApiProperty({
    example: 'Password@123',
    description:
      'Password (minimum 8 characters, will be hashed internally before saving)',
    minLength: 8,
  })
  @IsNotEmpty({ message: 'Password is required' })
  @IsString()
  @MinLength(8, { message: 'Password must be at least 8 characters long' })
  @Matches(/(?=.*[A-Z])/, {
    message: 'Password must contain at least one uppercase letter',
  })
  @Matches(/(?=.*[a-z])/, {
    message: 'Password must contain at least one lowercase letter',
  })
  @Matches(/(?=.*\d)/, {
    message: 'Password must contain at least one digit',
  })
  @Matches(/(?=.*[!@#$%^&*(),.?":{}|<>])/,
    { message: 'Password must contain at least one special character (!@#$%^&*)' })
  password: string;
}
