# Imagen del Dashboard Web de Portero Cloud. Multi-etapa: la etapa "build" tiene Node y compila
# la SPA (tsc --noEmit + vite build); la etapa final solo lleva nginx y los archivos estáticos.
#
# H-64: las imágenes base van fijadas por digest (la etiqueta queda como referencia) y Dependabot
# las actualiza.

# ---------- Etapa 1: construcción ----------
FROM node:22-alpine@sha256:0a7108bf6c7bf5de370ffb1a3ed6be93d405b43ff159f681a8d18c0e2bc2e402 AS build

WORKDIR /app

# Primero solo las dependencias: esta capa se reutiliza mientras no cambie package-lock.json.
# --ignore-scripts (H-64): ningún paquete ejecuta código al instalarse. El build solo necesita tsc
# y vite; esbuild trae su binario como dependencia opcional por plataforma y no necesita su
# postinstall.
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund --ignore-scripts

COPY . .
RUN npm run build

# ---------- Etapa 2: ejecución ----------
# nginx sin privilegios: la imagen oficial "unprivileged" corre como el usuario nginx (UID 101),
# escucha en el 8080 (un puerto < 1024 exigiría root o CAP_NET_BIND_SERVICE) y escribe sus
# temporales en /tmp, lo que permite un sistema de archivos de solo lectura en Compose.
FROM nginxinc/nginx-unprivileged:1.28-alpine@sha256:7377697a821c131a924a7105fafbe7414db4e9fcc77a6f08f776f33f141ec3f8 AS runtime

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY security-headers.conf /etc/nginx/security-headers.conf
# H-79: el entrypoint de la imagen ejecuta los *.sh de /docker-entrypoint.d/ al arrancar.
COPY --chmod=755 docker-entrypoint.d/40-portero-realip.sh /docker-entrypoint.d/
COPY --from=build /app/dist /usr/share/nginx/html

USER 101
EXPOSE 8080

# H-63 (CIS Docker 4.6): wget es el de busybox (Alpine). Solo pide index.html, no toca la API.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --start-interval=2s --retries=3     CMD ["wget", "-q", "--spider", "http://127.0.0.1:8080/"]
