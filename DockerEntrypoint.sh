#!/bin/sh
set -eu
# fail2ban is optional; an unavailable firewall backend must not prevent the
# panel or explicit maintenance/version commands from starting.
if [ "${XUI_FAIL2BAN_ENABLED:-true}" = true ] && [ "${1:-}" = /app/x-ui ] && [ "$#" -eq 1 ]; then
    fail2ban-client -x start || echo "fail2ban could not start; panel is continuing" >&2
fi
exec "$@"
