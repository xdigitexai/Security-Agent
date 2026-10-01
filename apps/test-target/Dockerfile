FROM node:22-bookworm-slim
WORKDIR /app
COPY package*.json ./
COPY apps/test-target/package.json apps/test-target/package.json
RUN npm install
COPY apps/test-target apps/test-target
CMD ["npm","run","dev","-w","@xdigitex/test-target"]
