CREATE TYPE "TestIdentityAuthType" AS ENUM ('BEARER','COOKIE','HEADERS');
CREATE TYPE "TestSessionState" AS ENUM ('ACTIVE','REVOKED');
CREATE TYPE "TestResourceExpectation" AS ENUM ('DENY_COMPARATORS','PUBLIC');

CREATE TABLE "TestIdentity" (
  "id" UUID NOT NULL,
  "assetId" UUID NOT NULL,
  "label" TEXT NOT NULL,
  "roleLabel" TEXT NOT NULL,
  "tenantLabel" TEXT,
  "authType" "TestIdentityAuthType" NOT NULL,
  "encryptedSecret" TEXT NOT NULL,
  "secretIv" TEXT NOT NULL,
  "secretTag" TEXT NOT NULL,
  "expectedSessionState" "TestSessionState" NOT NULL DEFAULT 'ACTIVE',
  "enabled" BOOLEAN NOT NULL DEFAULT true,
  "expiresAt" TIMESTAMP(3),
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "TestIdentity_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "TestResource" (
  "id" UUID NOT NULL,
  "assetId" UUID NOT NULL,
  "label" TEXT NOT NULL,
  "url" TEXT NOT NULL,
  "method" TEXT NOT NULL DEFAULT 'GET',
  "ownerIdentityId" UUID NOT NULL,
  "comparatorIdentityIds" JSONB NOT NULL,
  "expectation" "TestResourceExpectation" NOT NULL DEFAULT 'DENY_COMPARATORS',
  "proofMarker" TEXT,
  "safeReadOnly" BOOLEAN NOT NULL DEFAULT true,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "TestResource_pkey" PRIMARY KEY ("id")
);

CREATE INDEX "TestIdentity_assetId_enabled_idx" ON "TestIdentity"("assetId","enabled");
CREATE INDEX "TestResource_assetId_idx" ON "TestResource"("assetId");
ALTER TABLE "TestIdentity" ADD CONSTRAINT "TestIdentity_assetId_fkey" FOREIGN KEY ("assetId") REFERENCES "Asset"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "TestResource" ADD CONSTRAINT "TestResource_assetId_fkey" FOREIGN KEY ("assetId") REFERENCES "Asset"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "TestResource" ADD CONSTRAINT "TestResource_ownerIdentityId_fkey" FOREIGN KEY ("ownerIdentityId") REFERENCES "TestIdentity"("id") ON DELETE CASCADE ON UPDATE CASCADE;
