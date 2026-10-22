"""Read-only remote inventory script.

The scanner feeds this script to `sh -s` over SSH. It does not accept
user-supplied shell fragments and never changes remote state.
"""

REMOTE_AUDIT_SCRIPT = r"""
set +e

clean() {
    printf '%s' "$1" | tr '\t\r\n' '   '
}

emit() {
    printf '%s\t%s\n' "$1" "$(clean "$2")"
}

run_cap() {
    seconds="$1"
    shift
    if command -v timeout >/dev/null 2>&1; then
        timeout "$seconds" "$@"
    else
        "$@"
    fi
}

emit META "host=$(hostname -f 2>/dev/null || hostname 2>/dev/null || echo unknown)"
emit META "kernel=$(uname -srmo 2>/dev/null || uname -a 2>/dev/null || echo unknown)"
emit META "date=$(date -Iseconds 2>/dev/null || date 2>/dev/null || echo unknown)"
emit META "uid=$(id -u 2>/dev/null || echo unknown)"

if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release 2>/dev/null
    emit META "os=${PRETTY_NAME:-${NAME:-Linux} ${VERSION:-}}"
fi

if command -v systemctl >/dev/null 2>&1; then
    run_cap 10 systemctl list-units --type=service --all --no-pager 2>/dev/null \
        | grep -Ei 'php|apache|httpd|nginx|litespeed|openlitespeed|franken|caddy' \
        | head -n 200 \
        | while IFS= read -r line; do emit SERVICE "$line"; done
fi

ps -eo user,pid,ppid,args 2>/dev/null \
    | grep -E '[p]hp|[a]pache2|[h]ttpd|[l]itespeed|[f]rankenphp|[l]sphp' \
    | grep -v 'remote_audit' \
    | head -n 250 \
    | while IFS= read -r line; do emit PROCESS "$line"; done

for ctl in apache2ctl httpd; do
    if command -v "$ctl" >/dev/null 2>&1; then
        run_cap 8 "$ctl" -M 2>&1 \
            | grep -Ei 'php.*module|mpm_' \
            | head -n 40 \
            | while IFS= read -r line; do emit APACHE_MODULE "$line"; done
        break
    fi
done

if command -v dpkg-query >/dev/null 2>&1; then
    dpkg-query -W -f='${Package}=${Version}\n' 'php*' 'libapache2-mod-php*' 2>/dev/null \
        | head -n 300 \
        | while IFS= read -r line; do emit PACKAGE "dpkg:$line"; done
fi

if command -v rpm >/dev/null 2>&1; then
    rpm -qa 'php*' 2>/dev/null \
        | sort \
        | head -n 300 \
        | while IFS= read -r line; do emit PACKAGE "rpm:$line"; done
fi

candidates="$(
    {
        command -v php 2>/dev/null
        command -v php-fpm 2>/dev/null
        command -v php-cgi 2>/dev/null
        find /www/server/php /usr/local /opt -maxdepth 5 -type f \
            \( -name php -o -name 'php-fpm' -o -name 'php-cgi' \) 2>/dev/null
    } | sort -u
)"

printf '%s\n' "$candidates" \
    | while IFS= read -r bin; do
        [ -n "$bin" ] || continue
        [ -x "$bin" ] || continue
        real="$(readlink -f "$bin" 2>/dev/null || printf '%s' "$bin")"
        first="$(run_cap 8 "$bin" -v 2>&1 | grep -m1 '^PHP [0-9]')"
        printf '%s' "$first" | grep -q '^PHP [0-9]' || continue
        case "$real" in
            *php-fpm*) kind='fpm' ;;
            *php-cgi*) kind='cgi' ;;
            */php|php) kind='php' ;;
            *) kind='other' ;;
        esac
        emit BIN "$real|$kind|$first"
        run_cap 8 "$bin" -i 2>/dev/null \
            | grep -E '^(Configure Command|Server API|Loaded Configuration File|memory_limit|post_max_size|upload_max_filesize|session\.upload_progress\.enabled|fatal_error_backtraces|max_input_nesting_level|max_file_uploads) =>' \
            | head -n 40 \
            | while IFS= read -r setting; do emit SETTING "$real|$setting"; done
    done

for pattern in \
    '/www/server/php/*/etc/php-fpm.conf' \
    '/www/server/php/*/etc/php-fpm.d/*.conf' \
    '/etc/php/*/fpm/php-fpm.conf' \
    '/etc/php/*/fpm/pool.d/*.conf'
do
    for file in $pattern; do
        [ -f "$file" ] || continue
        grep -HnE '^[[:space:]]*(php_admin_value|php_admin_flag|php_value|php_flag)\[(memory_limit|post_max_size|upload_max_filesize|session\.upload_progress\.enabled|fatal_error_backtraces)\]' "$file" 2>/dev/null \
            | head -n 200 \
            | while IFS= read -r line; do emit POOL_SETTING "$line"; done
    done
done

if command -v docker >/dev/null 2>&1; then
    run_cap 12 docker ps --format '{{.Names}}|{{.Image}}' 2>/dev/null \
        | head -n 30 \
        | while IFS='|' read -r name image; do
            [ -n "$name" ] || continue
            first="$(run_cap 15 docker exec "$name" php -v 2>/dev/null | grep -m1 '^PHP [0-9]')"
            if printf '%s' "$first" | grep -q '^PHP [0-9]'; then
                emit DOCKER_PHP "$name|$image|$first"
                run_cap 15 docker exec "$name" php -i 2>/dev/null \
                    | grep -E '^(Server API|memory_limit|post_max_size|upload_max_filesize|session\.upload_progress\.enabled|fatal_error_backtraces|max_input_nesting_level|max_file_uploads) =>' \
                    | head -n 40 \
                    | while IFS= read -r setting; do emit DOCKER_SETTING "$name|$setting"; done
                for ctl in apache2ctl httpd; do
                    if run_cap 15 docker exec "$name" sh -lc "command -v $ctl" >/dev/null 2>&1; then
                        run_cap 15 docker exec "$name" "$ctl" -M 2>/dev/null \
                            | grep -Ei 'php.*module|mpm_' \
                            | while IFS= read -r line; do emit DOCKER_APACHE_MODULE "$name|$line"; done
                        break
                    fi
                done
            fi
        done
fi

emit END "done"
"""
