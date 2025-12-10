-- CreateEnum
CREATE TYPE "UserRole" AS ENUM ('USER', 'ADMIN');

-- CreateEnum
CREATE TYPE "AuthProvider" AS ENUM ('LOCAL', 'GOOGLE');

-- CreateEnum
CREATE TYPE "OtpType" AS ENUM ('SIGNUP', 'PASSWORD_RESET', 'EMAIL_VERIFY');

-- CreateTable
CREATE TABLE "users" (
    "id" TEXT NOT NULL,
    "first_name" TEXT NOT NULL,
    "last_name" TEXT,
    "email" TEXT NOT NULL,
    "phone_number" TEXT,
    "password_hash" TEXT,
    "provider" "AuthProvider" NOT NULL DEFAULT 'LOCAL',
    "googleId" TEXT,
    "role" "UserRole" NOT NULL DEFAULT 'USER',
    "is_email_verified" BOOLEAN NOT NULL DEFAULT false,
    "currentHashedRefreshToken" TEXT,
    "profile_image_url" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "users_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "email_otp" (
    "id" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "otp_code" TEXT NOT NULL,
    "otpHash" TEXT NOT NULL,
    "type" "OtpType" NOT NULL,
    "attemptCount" INTEGER NOT NULL DEFAULT 0,
    "expires_at" TIMESTAMP(3) NOT NULL,
    "is_used" BOOLEAN NOT NULL DEFAULT false,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "userId" TEXT,

    CONSTRAINT "email_otp_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ResetToken" (
    "id" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "token" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ResetToken_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "admin_activity_logs" (
    "id" TEXT NOT NULL,
    "admin_id" TEXT NOT NULL,
    "action" TEXT NOT NULL,
    "target_id" TEXT NOT NULL,
    "target_table" TEXT NOT NULL,
    "ip_address" TEXT,
    "details" JSONB,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "admin_activity_logs_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "users_email_key" ON "users"("email");

-- CreateIndex
CREATE UNIQUE INDEX "users_phone_number_key" ON "users"("phone_number");

-- CreateIndex
CREATE UNIQUE INDEX "users_googleId_key" ON "users"("googleId");

-- CreateIndex
CREATE INDEX "email_otp_email_type_is_used_idx" ON "email_otp"("email", "type", "is_used");

-- CreateIndex
CREATE UNIQUE INDEX "ResetToken_token_key" ON "ResetToken"("token");

-- AddForeignKey
ALTER TABLE "email_otp" ADD CONSTRAINT "email_otp_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "admin_activity_logs" ADD CONSTRAINT "admin_activity_logs_admin_id_fkey" FOREIGN KEY ("admin_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
