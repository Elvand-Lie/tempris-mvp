# demo/frontend/Dockerfile — builds the React app inside Docker so a fresh
# checkout needs no local Node. Run as the compose `webdist` one-shot service:
# it builds ./dist and copies the assets into the shared `dist` volume that
# the edge service serves.
FROM node:22-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY . .
RUN npm run build

FROM alpine:3.20
COPY --from=build /app/dist /dist
# Publish the built assets to the shared volume mounted at /out.
CMD ["sh", "-c", "cp -r /dist/. /out/"]
