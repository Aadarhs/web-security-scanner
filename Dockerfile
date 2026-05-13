FROM node:18-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --omit=dev

COPY . .

RUN mkdir -p database reports/generated

EXPOSE 3000

ENV NODE_ENV=production

RUN node database/seed.js

CMD ["node", "server/index.js"]