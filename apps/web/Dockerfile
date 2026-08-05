FROM node:22-alpine AS build

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY . .
ARG VITE_API_BASE_URL=/api/v1
ARG VITE_OIDC_AUTHORIZATION_URL=
ARG VITE_OIDC_TOKEN_URL=
ARG VITE_OIDC_CLIENT_ID=
ARG VITE_OIDC_REDIRECT_URI=
ARG VITE_OIDC_SCOPES=
ENV VITE_API_BASE_URL=${VITE_API_BASE_URL}
ENV VITE_OIDC_AUTHORIZATION_URL=${VITE_OIDC_AUTHORIZATION_URL}
ENV VITE_OIDC_TOKEN_URL=${VITE_OIDC_TOKEN_URL}
ENV VITE_OIDC_CLIENT_ID=${VITE_OIDC_CLIENT_ID}
ENV VITE_OIDC_REDIRECT_URI=${VITE_OIDC_REDIRECT_URI}
ENV VITE_OIDC_SCOPES=${VITE_OIDC_SCOPES}
RUN npm run build

FROM nginxinc/nginx-unprivileged:1.29-alpine AS runtime

ENV OIDC_CONNECT_SRC="" \
    NGINX_ENVSUBST_FILTER=OIDC_CONNECT_SRC

COPY nginx.conf /etc/nginx/templates/default.conf.template
COPY --from=build /app/dist /usr/share/nginx/html

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1:8080/healthz || exit 1
