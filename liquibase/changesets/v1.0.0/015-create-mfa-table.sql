--liquibase formatted sql

--changeset devlucashaubmann:015-create-mfa-table
CREATE TABLE "mfa" (
    "id" SERIAL PRIMARY KEY,
    "user_id" INTEGER NOT NULL UNIQUE REFERENCES "user"("id") ON DELETE CASCADE,
    "secret" TEXT,
    "pending_secret" TEXT,
    "enabled" BOOLEAN NOT NULL DEFAULT FALSE,
    "last_used_step" INTEGER,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT NOW(),
    "updated_at" TIMESTAMPTZ(3) NOT NULL DEFAULT NOW(),
    CONSTRAINT "mfa_enabled_matches_secret" CHECK ("enabled" = ("secret" IS NOT NULL))
);
--rollback DROP TABLE "mfa";
