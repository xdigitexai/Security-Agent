FROM node:22-bookworm-slim
WORKDIR /app
COPY package*.json ./
COPY apps/worker/package.json apps/worker/package.json
COPY packages/database/package.json packages/database/package.json
COPY packages/scanner-core/package.json packages/scanner-core/package.json
COPY packages/security-checks/package.json packages/security-checks/package.json
COPY packages/shared/package.json packages/shared/package.json
COPY packages/types/package.json packages/types/package.json
RUN npm install
COPY . .
RUN npx playwright install --with-deps chromium && npm run db:generate
CMD ["npm","run","dev","-w","@xdigitex/worker"]
