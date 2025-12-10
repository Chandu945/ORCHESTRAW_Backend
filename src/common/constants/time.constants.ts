export class AppConstants{

    static readonly OTP_EXPIRY_MINUTES = 5;       // OTP valid for 5 minutes
    static readonly OTP_COOLDOWN_SECONDS = 25;    // 25-sec cooldown between resend
    static readonly OTP_MAX_ATTEMPTS = 5;         // Maximum allowed wrong attempts
    static readonly OTP_LENGTH = 6;               // 6-digit OTP
    static readonly OTP_REST_EXPIR_MINUTES=5;     // 

  // Bcrypt
    static readonly BCRYPT_SALT_ROUNDS = 10;      // Hash strength
    static  readonly OTP_COOLDOWN_MS = 30 * 1000; 
}