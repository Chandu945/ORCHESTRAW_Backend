-- CreateEnum
CREATE TYPE "BandAccountStatus" AS ENUM ('PENDING_VERIFICATION', 'ACTIVE', 'SUSPENDED');

-- CreateEnum
CREATE TYPE "BandOtpPurpose" AS ENUM ('EMAIL_VERIFY', 'PASSWORD_RESET');

-- CreateTable
CREATE TABLE "band_accounts" (
    "id" TEXT NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,
    "band_name" TEXT NOT NULL,
    "owner_name" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "phone_number" TEXT NOT NULL,
    "password_hash" TEXT NOT NULL,
    "email_verified" BOOLEAN NOT NULL DEFAULT false,
    "status" "BandAccountStatus" NOT NULL DEFAULT 'PENDING_VERIFICATION',
    "refresh_token_hash" TEXT,

    CONSTRAINT "band_accounts_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "band_otps" (
    "id" TEXT NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "band_account_id" TEXT NOT NULL,
    "purpose" "BandOtpPurpose" NOT NULL,
    "code_hash" TEXT NOT NULL,
    "expires_at" TIMESTAMP(3) NOT NULL,
    "used_at" TIMESTAMP(3),
    "attempts" INTEGER NOT NULL DEFAULT 0,
    "last_sent_at" TIMESTAMP(3),

    CONSTRAINT "band_otps_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "band_accounts_email_key" ON "band_accounts"("email");

-- CreateIndex
CREATE UNIQUE INDEX "band_accounts_phone_number_key" ON "band_accounts"("phone_number");

-- CreateIndex
CREATE INDEX "band_otps_band_account_id_purpose_idx" ON "band_otps"("band_account_id", "purpose");

-- AddForeignKey
ALTER TABLE "band_otps" ADD CONSTRAINT "band_otps_band_account_id_fkey" FOREIGN KEY ("band_account_id") REFERENCES "band_accounts"("id") ON DELETE CASCADE ON UPDATE CASCADE;
