import { IsEmail, IsNotEmpty, IsString, Length } from "class-validator";

export class VerifyResetOtpDto {
  @IsNotEmpty({message:"Please provide your email address to proceed."})
  @IsEmail({},{message:"Please Enter Valid Email"})
  email: string;

  @IsNotEmpty()
  @IsString()
  @Length(6, 6)
  otp: string;
}