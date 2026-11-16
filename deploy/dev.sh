#!/bin/bash
# Local test of the production quadlets as the CURRENT user.
#
# Renders deploy/quadlet/*.{container,build} into ~/.config/containers/systemd/ as
# wash-web-dev.* with dev paths substituted (state in ~/.local/share/wash-dev, image
# built from this checkout, own port), so the units under test are the ones that
# get published to the wash service user — only paths and names differ.
#
#   deploy/dev.sh install     render units, write .env, daemon-reload
#   deploy/dev.sh start|stop|restart|status|logs
#   deploy/dev.sh rebuild     rebuild the image from this checkout and restart
#   deploy/dev.sh enroll      same as `wash enroll` (kept for muscle memory)
#   deploy/dev.sh exec ARGS   run wash-web ARGS in the container (keys, managers, ...)
#   deploy/dev.sh backup      run the backup script against the dev paths
#   deploy/dev.sh dryrun      show the quadlet generator output
#   deploy/dev.sh uninstall   remove units and container (keeps state unless --purge)
set -euo pipefail
REPO=$(cd "$(dirname "$0")/.." && pwd)
DEV=${WASH_DEV_DIR:-$HOME/.local/share/wash-dev}
PORT=${WASH_DEV_PORT:-8443}
QDIR=$HOME/.config/containers/systemd
NAME=wash-web-dev

render() {
	sed -e "s#/data-active/wash#$DEV/data#g" \
	    -e "s#/data/backups/wash#$DEV/backup#g" \
	    -e "s#%h/wash-web/.env#$DEV/.env#g" \
	    -e "s#%h/wash-web#$REPO#g" \
	    -e "s#^Image=wash-web.build#Image=$NAME.build#" \
	    -e "s#^ImageTag=localhost/wash-web:latest#ImageTag=localhost/wash-web:dev#" \
	    -e "s#^ContainerName=wash-web#ContainerName=$NAME#" \
	    -e "s#^PublishPort=8443:8443#PublishPort=$PORT:8443#" \
	    -e "s#^Description=wash-web#Description=[dev] wash-web#" \
	    "$1"
}

case "${1:-}" in
install)
	install -d -m 0700 "$DEV" "$DEV/data" "$DEV/backup"
	if [ ! -f "$DEV/.env" ]; then
		h=$(hostname)
		# tailnet MagicDNS name, if any (passkeys need a name, not the 100.x address)
		ts=$(tailscale status --json 2>/dev/null | sed -n 's/.*"DNSName": *"\([^"]*\)\.".*/\1/p' | head -1)
		umask 077
		sed -e "s#^WASH_ORIGIN=.*#WASH_ORIGIN=${ts:+https://$ts:$PORT,}https://$h:$PORT,https://localhost:$PORT#" \
		    -e "s#^WASH_TLS_HOSTS=.*#WASH_TLS_HOSTS=${ts:+$ts,}$h#" \
		    "$REPO/deploy/env.example" > "$DEV/.env"
		echo "wrote $DEV/.env (edit WASH_ORIGIN for other names)"
	fi
	mkdir -p "$QDIR"
	render "$REPO/deploy/quadlet/wash-web.container" > "$QDIR/$NAME.container"
	render "$REPO/deploy/quadlet/wash-web.build" > "$QDIR/$NAME.build"
	systemctl --user daemon-reload
	echo "installed $QDIR/$NAME.{container,build}; start with: $0 start"
	;;
start|stop|restart|status)
	systemctl --user "$1" "$NAME.service" ${2:+"$2"} ;;
logs)
	journalctl --user -u "$NAME.service" -n 100 -f ;;
rebuild)
	podman build -t localhost/wash-web:dev -f "$REPO/Containerfile.build" "$REPO"
	systemctl --user restart "$NAME.service" ;;
enroll)
	exec "$REPO/bin/wash" enroll "https://$(hostname):$PORT" ;;
exec)
	shift; podman exec "$NAME" /wash-web "$@" ;;
backup)
	sed -e "s#/data/backups/wash#$DEV/backup#g; s#/data-active/wash#$DEV/data#g; s#podman exec wash-web#podman exec $NAME#" \
	    "$REPO/deploy/bin/wash-web-backup.sh" | bash
	ls -l "$DEV/backup" ;;
dryrun)
	/usr/libexec/podman/quadlet -dryrun -user 2>&1 | sed -n "/$NAME/,/^---/p" ;;
uninstall)
	systemctl --user stop "$NAME.service" 2>/dev/null || true
	rm -f "$QDIR/$NAME.container" "$QDIR/$NAME.build"
	systemctl --user daemon-reload
	podman rm -f "$NAME" >/dev/null 2>&1 || true
	[ "${2:-}" = --purge ] && rm -rf "$DEV" && echo "removed $DEV"
	echo uninstalled ;;
*)
	sed -n '2,20p' "$0"; exit 2 ;;
esac
