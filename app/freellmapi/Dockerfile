FROM node:20

WORKDIR /app

COPY package.json package-lock.json ./

RUN npm ci

COPY . .

RUN npm run build

RUN mkdir -p /app/data

EXPOSE 3001

CMD ["node", "dist/index.js"]
