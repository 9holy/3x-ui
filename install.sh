#!/bin/bash
# Install or upgrade the public 9holy/3x-ui release. Usage: bash install.sh [v2.4.3]
# Sourcing this file only defines functions, for isolated delivery regression tests.
set -Eeuo pipefail
umask 077

REPOSITORY="9holy/3x-ui"
INSTALL_DIR="/usr/local/x-ui"
DB_PATH="${XUI_DB_FOLDER:-/etc/x-ui}/x-ui.db"
MENU_PATH="/usr/bin/x-ui"
UNIT_PATH="/etc/systemd/system/x-ui.service"
WORK_DIR=""
BACKUP_DIR=""
transaction=false
was_running=false
was_enabled=false
program_moved=false
program_installed=false
files_backed_up=false

fail() { echo "Error: $*" >&2; return 1; }

architecture() {
    case "$(uname -m)" in
        x86_64|x64|amd64) echo amd64 ;;
        i?86|x86) echo 386 ;;
        aarch64|arm64|armv8*) echo arm64 ;;
        armv7*|arm) echo armv7 ;;
        armv6*) echo armv6 ;;
        armv5*) echo armv5 ;;
        s390x) echo s390x ;;
        *) fail "Unsupported CPU architecture: $(uname -m)" ;;
    esac
}

install_dependencies() {
    # Do not update the whole OS as a side effect of installing this panel.
    if command -v curl >/dev/null && command -v python3 >/dev/null && command -v tar >/dev/null; then
        return
    fi
    if command -v apt-get >/dev/null; then
        apt-get update
        apt-get install -y curl python3 tar ca-certificates
    elif command -v dnf >/dev/null; then
        dnf install -y curl python3 tar ca-certificates
    elif command -v yum >/dev/null; then
        yum install -y curl python3 tar ca-certificates
    elif command -v pacman >/dev/null; then
        pacman -S --needed --noconfirm curl python tar ca-certificates
    elif command -v zypper >/dev/null; then
        zypper --non-interactive install curl python3 tar ca-certificates
    else
        fail "Install curl, Python 3, tar and CA certificates, then run this command again."
    fi
}

fetch() {
    curl --fail --show-error --silent --location --proto '=https' --proto-redir '=https' \
        --connect-timeout 20 --max-time 600 --retry 3 --output "$2" "$1"
}

release_tag() {
    local requested="${1:-}"
    if [[ -n "$requested" ]]; then
        requested="v${requested#v}"
    else
        fetch "https://api.github.com/repos/$REPOSITORY/releases/latest" "$WORK_DIR/latest.json" || return 1
        requested=$(python3 - "$WORK_DIR/latest.json" <<'PY'
import json,sys
release=json.load(open(sys.argv[1]))
if release.get('draft') or release.get('prerelease'):
    raise SystemExit('The latest release is not a public stable release')
print(release['tag_name'])
PY
) || return 1
    fi
    if [[ ! "$requested" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        fail "Invalid release version: $requested"
        return 1
    fi
    printf '%s\n' "$requested"
}

verify_asset() {
    python3 - "$1" "$2" <<'PY'
import hashlib,pathlib,sys
asset=pathlib.Path(sys.argv[1]); entries={}
for line in pathlib.Path(sys.argv[2]).read_text().splitlines():
    digest,name=line.split('  ',1)
    if name in entries or pathlib.PurePosixPath(name).name != name:
        raise SystemExit('Invalid checksum manifest')
    entries[name]=digest
expected=entries.get(asset.name)
if expected is None:
    raise SystemExit('Release checksum is missing: '+asset.name)
hash=hashlib.sha256()
with asset.open('rb') as source:
    for chunk in iter(lambda:source.read(1024*1024),b''):
        hash.update(chunk)
if hash.hexdigest()!=expected:
    raise SystemExit('Release checksum mismatch: '+asset.name)
PY
}

extract_package() {
    python3 - "$1" "$2" <<'PY'
import pathlib,sys,tarfile
seen=set()
with tarfile.open(sys.argv[1],'r:gz') as archive:
    members=archive.getmembers()
    for item in members:
        path=pathlib.PurePosixPath(item.name)
        if path.is_absolute() or '..' in path.parts or not path.parts or path.parts[0]!='x-ui':
            raise SystemExit('Unsafe archive path: '+item.name)
        if path in seen or not (item.isfile() or item.isdir()):
            raise SystemExit('Duplicate, linked or special archive entry: '+item.name)
        seen.add(path)
    # Validation rejects every link and special file, including on Python <3.12.
    archive.extractall(sys.argv[2],members=members)
PY
}

preflight() {
    local candidate="$1" current_dir
    current_dir="$candidate"
    [[ ! -d "$INSTALL_DIR" ]] || current_dir="$INSTALL_DIR"
    (
        cd "$current_dir"
        XUI_BIN_FOLDER="$candidate/bin" XRAY_LOCATION_ASSET="$candidate/bin" \
            "$candidate/x-ui" check -db "$DB_PATH"
    )
}

backup_state() {
    mkdir -p "$BACKUP_DIR"
    chmod 700 "$BACKUP_DIR"
    local suffix
    for suffix in '' '-wal' '-shm'; do
        [[ ! -e "$DB_PATH$suffix" ]] || cp -a "$DB_PATH$suffix" "$BACKUP_DIR/database$suffix"
    done
    [[ ! -e "$MENU_PATH" ]] || cp -a "$MENU_PATH" "$BACKUP_DIR/menu"
    [[ ! -e "$UNIT_PATH" ]] || cp -a "$UNIT_PATH" "$BACKUP_DIR/unit"
    files_backed_up=true
}

restore_file() {
    local source="$1" destination="$2"
    if [[ -e "$source" ]]; then
        cp -a "$source" "$destination"
    else
        rm -f "$destination"
    fi
}

rollback() {
    echo "Upgrade did not complete; restoring the previous installation." >&2
    systemctl stop x-ui >/dev/null 2>&1 || true
    if $program_installed; then
        rm -rf "$INSTALL_DIR"
    fi
    if $program_moved; then
        mv "$BACKUP_DIR/program" "$INSTALL_DIR" || return 1
    fi
    if $files_backed_up; then
        local suffix
        for suffix in '' '-wal' '-shm'; do
            restore_file "$BACKUP_DIR/database$suffix" "$DB_PATH$suffix" || return 1
        done
        restore_file "$BACKUP_DIR/menu" "$MENU_PATH" || return 1
        restore_file "$BACKUP_DIR/unit" "$UNIT_PATH" || return 1
    fi
    systemctl daemon-reload || return 1
    if [[ -f "$UNIT_PATH" ]]; then
        if $was_enabled; then systemctl enable x-ui || return 1; else systemctl disable x-ui || return 1; fi
        if $was_running; then systemctl start x-ui || return 1; fi
    fi
    echo "Previous program, database and service state restored. Backup: $BACKUP_DIR" >&2
}

finish() {
    local status="$1"
    set +e
    if (( status != 0 )) && $transaction; then
        rollback || echo "Automatic rollback failed. Recover from $BACKUP_DIR and check journalctl -u x-ui." >&2
    fi
    [[ -z "$WORK_DIR" ]] || rm -rf "$WORK_DIR"
    exit "$status"
}

verify_started() {
    # systemctl start alone can succeed while a process immediately crashes.
    local round
    for round in 1 2 3 4 5; do
        sleep 1
        systemctl is-active --quiet x-ui || return 1
    done
}

apply_installation() {
    local candidate="$1"
    systemctl is-active --quiet x-ui && was_running=true
    systemctl is-enabled --quiet x-ui && was_enabled=true
    BACKUP_DIR="$INSTALL_DIR.backup.$(date -u +%Y%m%dT%H%M%SZ).$$"
    mkdir -p "$BACKUP_DIR"
    transaction=true
    if [[ -f "$UNIT_PATH" ]] || $was_running; then systemctl stop x-ui; fi
    backup_state
    if [[ -d "$INSTALL_DIR" ]]; then
        # Keep relative certificates and local configuration; packaged files win.
        cp -a -n "$INSTALL_DIR/." "$candidate/"
        mv "$INSTALL_DIR" "$BACKUP_DIR/program"
        program_moved=true
    fi
    mv "$candidate" "$INSTALL_DIR"
    program_installed=true
    mkdir -p "$(dirname "$MENU_PATH")" "$(dirname "$UNIT_PATH")" "$(dirname "$DB_PATH")"
    install -m 755 "$INSTALL_DIR/x-ui.sh" "$MENU_PATH"
    # Keep existing systemd environment/customization on upgrades.
    if [[ ! -f "$UNIT_PATH" ]]; then install -m 644 "$INSTALL_DIR/x-ui.service" "$UNIT_PATH"; fi
    if [[ ! -f "$DB_PATH" ]]; then
        local username password basepath
        username=$(python3 -c 'import secrets; print(secrets.token_hex(6))')
        password=$(python3 -c 'import secrets; print(secrets.token_urlsafe(18))')
        basepath=$(python3 -c 'import secrets; print(secrets.token_urlsafe(12))')
        (cd "$INSTALL_DIR"; XUI_DB_FOLDER="$(dirname "$DB_PATH")" ./x-ui setting \
            -username "$username" -password "$password" -webBasePath "$basepath")
        [[ -s "$DB_PATH" ]] || fail "Fresh database initialization failed"
        printf '\nNew panel login:\nUsername: %s\nPassword: %s\nBase path: /%s/\nPort: 2053\n' "$username" "$password" "$basepath"
    fi
    (cd "$INSTALL_DIR"; XUI_DB_FOLDER="$(dirname "$DB_PATH")" ./x-ui migrate)
    systemctl daemon-reload
    systemctl enable x-ui
    systemctl start x-ui
    verify_started || fail "New service did not stay running; inspect journalctl -u x-ui"
    transaction=false
    echo "Installation complete. Existing settings were preserved. Backup: $BACKUP_DIR"
    echo "Use x-ui to manage the panel, or x-ui settings to view its address."
}

main() {
    [[ $EUID -eq 0 ]] || fail "Run this installer as root."
    [[ $(uname -s) == Linux ]] || fail "This installer requires Linux."
    command -v systemctl >/dev/null || fail "This installer requires systemd."
    install_dependencies
    local platform tag archive candidate actual
    platform=$(architecture)
    WORK_DIR=$(mktemp -d /usr/local/.xui-install.XXXXXXXX)
    trap 'finish $?' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    trap 'exit 129' HUP
    tag=$(release_tag "${1:-}")
    archive="x-ui-linux-$platform.tar.gz"
    echo "Installing $REPOSITORY $tag ($platform)"
    fetch "https://github.com/$REPOSITORY/releases/download/$tag/$archive" "$WORK_DIR/$archive"
    fetch "https://github.com/$REPOSITORY/releases/download/$tag/SHA256SUMS" "$WORK_DIR/SHA256SUMS"
    verify_asset "$WORK_DIR/$archive" "$WORK_DIR/SHA256SUMS"
    extract_package "$WORK_DIR/$archive" "$WORK_DIR"
    candidate="$WORK_DIR/x-ui"
    [[ -x "$candidate/x-ui" && -f "$candidate/x-ui.sh" && -f "$candidate/x-ui.service" ]] || fail "Incomplete release package"
    actual=$("$candidate/x-ui" -v)
    [[ "$actual" == "${tag#v}" ]] || fail "Release version mismatch: $actual"
    preflight "$candidate"
    apply_installation "$candidate"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
