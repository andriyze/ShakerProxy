# syntax=docker/dockerfile:1.12
FROM node:26.7.0-alpine@sha256:aadf416b2cdce311a8811ba3f0608a61b77dbf997500e2eafe781b51f6a0b019 AS build
WORKDIR /src
COPY apps/web-ui/package.json apps/web-ui/package-lock.json ./
RUN npm ci
COPY apps/web-ui ./
RUN npm run build

FROM nginx:1.29.1-alpine@sha256:42a516af16b852e33b7682d5ef8acbd5d13fe08fecadc7ed98605ba5e3b26ab8
COPY apps/web-ui/nginx.conf /etc/nginx/conf.d/default.conf
COPY apps/web-ui/nginx-main.conf /etc/nginx/nginx.conf
COPY --from=build /src/dist /usr/share/nginx/html
USER 101:101
EXPOSE 8080
ENTRYPOINT ["nginx", "-g", "daemon off;"]
