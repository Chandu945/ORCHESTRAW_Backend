import * as bcrypt from 'bcrypt';
import { randomInt } from 'crypto';
import { AppConstants } from '../constants/time.constants';

export class CryptoHelper {
  /** Internal shared hashing function */
  private static async hashValue(value: string): Promise<string> {
    const salt = await bcrypt.genSalt(AppConstants.BCRYPT_SALT_ROUNDS);
    return bcrypt.hash(value, salt);
  }

  /** Internal shared compare function */
  private static async compareValue(
    raw: string,
    hashed: string,
  ): Promise<boolean> {
    return bcrypt.compare(raw, hashed);
  }

  // ============================
  // PASSWORD METHODS
  // ============================

  /** Hash plain text password */
  static hashPassword(password: string): Promise<string> {
    return this.hashValue(password);
  }

  /** Compare plain password with hashed password */
  static comparePassword(
    plainPassword: string,
    hashedPassword: string,
  ): Promise<boolean> {
    return this.compareValue(plainPassword, hashedPassword);
  }

  // ============================
  // OTP METHODS
  // ============================

  /** Generate numeric OTP */
  static generateOtp(): string {
    let otp = '';
    for (let i = 0; i < AppConstants.OTP_LENGTH; i++) {
      otp += randomInt(0, 10).toString(); // random digit 0-9
    }
    return otp;
  }

  /** Hash OTP */
  static hashOtp(otp: string): Promise<string> {
    return this.hashValue(otp);
  }

  /** Compare OTP with hashed OTP */
  static compareOtp(
    plainOtp: string,
    hashedOtp: string,
  ): Promise<boolean> {
    return this.compareValue(plainOtp, hashedOtp);
  }
}
