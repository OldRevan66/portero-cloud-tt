#!/bin/sh
# H-79: IP real del cliente detrás de un proxy con TLS declarado por el operador (spec §7).
#
# El entrypoint de la imagen nginx ejecuta este script antes de arrancar nginx. Si
# PORTERO_TRUSTED_PROXY está vacía o no existe, no escribe nada y nginx se comporta igual que antes:
# un X-Forwarded-For del cliente siempre se ignora (H-53). Si trae una o varias IP o CIDR
# separadas por comas, escribe /tmp/portero-realip.conf (lo incluye nginx.conf) con:
#   set_real_ip_from <cada una>;     solo de esas IP se cree el X-Forwarded-For
#   real_ip_header X-Forwarded-For;  y de él se toma la última IP (la que agregó el proxy)
#
# Cada valor se valida contra una lista permitida de caracteres (dígitos, hexadecimales, ':', '.'
# y una máscara /n): así no se pueden inyectar directivas de nginx por la variable. Un valor
# inválido termina con error y el contenedor no arranca (falla visible, no silenciosa).
set -eu
set -f # sin comodines al separar la lista

DESTINO=/tmp/portero-realip.conf
rm -f "$DESTINO"

if [ -z "${PORTERO_TRUSTED_PROXY:-}" ]; then
    exit 0
fi

contenido=""
IFS=,
for valor in $PORTERO_TRUSTED_PROXY; do
    valor=$(printf '%s' "$valor" | tr -d ' ')
    # H-85: grep revisa línea por línea; un valor con saltos de línea pasaría si una sola línea
    # pareciera IP. Por eso primero se rechaza cualquier carácter fuera de la lista en TODO el valor.
    case "$valor" in
        "" | *[!0-9A-Fa-f:./]*)
            echo "$0: PORTERO_TRUSTED_PROXY no es una lista de IP o CIDR" >&2
            exit 1
            ;;
    esac
    if ! printf '%s' "$valor" | grep -Eq '^[0-9A-Fa-f:.]+(/[0-9]{1,3})?$'; then
        echo "$0: PORTERO_TRUSTED_PROXY no es una lista de IP o CIDR: '$valor'" >&2
        exit 1
    fi
    contenido="${contenido}set_real_ip_from ${valor};
"
done

printf '%sreal_ip_header X-Forwarded-For;\n' "$contenido" > "$DESTINO"
echo "$0: IP real del cliente tomada de X-Forwarded-For solo si viene de: $PORTERO_TRUSTED_PROXY"
