-- CreateEnum
CREATE TYPE "OrchestrawAccountStatus" AS ENUM ('ACTIVE', 'SUSPENDED');

-- CreateEnum
CREATE TYPE "OrchestrawOtpPurpose" AS ENUM ('EMAIL_VERIFY', 'PASSWORD_RESET');

-- CreateTable
CREATE TABLE "orchestraw_accounts" (
    "id" TEXT NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,
    "display_name" TEXT NOT NULL,
    "contact_name" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "phone_number" TEXT NOT NULL,
    "password_hash" TEXT NOT NULL,
    "email_verified" BOOLEAN NOT NULL DEFAULT true,
    "status" "OrchestrawAccountStatus" NOT NULL DEFAULT 'ACTIVE',
    "refresh_token_hash" TEXT,

    CONSTRAINT "orchestraw_accounts_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "orchestraw_otps" (
    "id" TEXT NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "email" TEXT NOT NULL,
    "purpose" "OrchestrawOtpPurpose" NOT NULL,
    "code_hash" TEXT NOT NULL,
    "expires_at" TIMESTAMP(3) NOT NULL,
    "used_at" TIMESTAMP(3),
    "attempts" INTEGER NOT NULL DEFAULT 0,
    "last_sent_at" TIMESTAMP(3),
    "account_id" TEXT,

    CONSTRAINT "orchestraw_otps_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "orchestraw_accounts_email_key" ON "orchestraw_accounts"("email");

-- CreateIndex
CREATE UNIQUE INDEX "orchestraw_accounts_phone_number_key" ON "orchestraw_accounts"("phone_number");

-- CreateIndex
CREATE INDEX "orchestraw_otps_email_purpose_idx" ON "orchestraw_otps"("email", "purpose");

-- AddForeignKey
ALTER TABLE "orchestraw_otps" ADD CONSTRAINT "orchestraw_otps_account_id_fkey" FOREIGN KEY ("account_id") REFERENCES "orchestraw_accounts"("id") ON DELETE CASCADE ON UPDATE CASCADE;
