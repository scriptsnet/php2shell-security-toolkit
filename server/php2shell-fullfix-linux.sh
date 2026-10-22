#!/usr/bin/env bash
#
# PHP2Shell 全流程检查/修复脚本（Linux）
#
# 漏洞：CVE-2026-109618 / CVE-2026-109619
# 修复版本：
#   PHP 8.2 -> 8.2.35
#   PHP 8.3 -> 8.3.36
#   PHP 8.4 -> 8.4.27
#   PHP 8.5 -> 8.5.12
#   宝塔 PHP 7.4 -> 7.4.34
#   宝塔 PHP 8.0 -> 8.0.27
#   宝塔 PHP 8.1 -> 8.1.35
#
# 默认只检查。真正执行必须显式加 --apply，并完成三次交互确认。
#
# 安全原则：
#   - 先做整机快照。脚本内备份只能覆盖脚本管理的 PHP 目录/容器文件。
#   - 自动修复仅覆盖可验证的宝塔标准安装和 Debian 系 PHP 官方镜像容器。
#   - 其他源码/发行版包/非标准容器不做盲改，只输出人工路径。
#   - 任一升级失败会尝试自动回滚该组件。
#

set -Eeuo pipefail
umask 077

CVE1='CVE-2026-109618'
CVE2='CVE-2026-109619'
BT_UPDATER_URL='https://download.bt.cn/install/0/php.sh'
BT_UPDATER_SHA256='db56c01dcef41212ec95aecad3d83543d4bfe1ae164d615c9733bb78abd81de6'
WORK_ROOT='/root/php2shell-fullfix'
STAMP="$(date '+%Y%m%d-%H%M%S')"
WORK_DIR="${WORK_ROOT}/${STAMP}"
LOG_FILE="${WORK_DIR}/run.log"
REPORT_FILE="${WORK_DIR}/report.txt"
PLAN_FILE="${WORK_DIR}/plan.txt"
BT_BACKUPS="${WORK_DIR}/bt-backups.tsv"
DOCKER_BACKUPS="${WORK_DIR}/docker-backups.tsv"
DOCKER_FILES="${WORK_DIR}/docker-files.tsv"
DOCKER_STOPPED="${WORK_DIR}/docker-stopped.tsv"
ROLLBACK_SCRIPT="${WORK_DIR}/rollback.sh"
MODE='check'
DO_BT=1
DO_DOCKER=1
STOP_UNFIXABLE=0
HTTP_URLS=()

usage() {
  awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --check) MODE='check'; shift ;;
    --apply) MODE='apply'; shift ;;
    --http-url)
      [ "$#" -ge 2 ] || { echo '--http-url 缺少参数' >&2; exit 2; }
      HTTP_URLS+=("$2"); shift 2 ;;
    --skip-bt) DO_BT=0; shift ;;
    --skip-docker) DO_DOCKER=0; shift ;;
    --stop-unfixable)
      STOP_UNFIXABLE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "未知参数：$1" >&2; usage >&2; exit 2 ;;
  esac
done

[ "$(id -u)" -eq 0 ] || {
  echo '必须使用 root 运行；检查模式也需要读取服务、容器和 PHP 目录。' >&2
  exit 1
}

for cmd in awk sed grep sort find tar sha256sum curl ps date hostname df du; do
  command -v "$cmd" >/dev/null 2>&1 || {
    echo "缺少命令：$cmd" >&2
    exit 1
  }
done

mkdir -p "$WORK_ROOT" "$WORK_DIR"
chmod 700 "$WORK_ROOT" "$WORK_DIR"
ln -sfn "$WORK_DIR" "${WORK_ROOT}/latest"
exec 9>"${WORK_ROOT}/fullfix.lock"
if command -v flock >/dev/null 2>&1; then
  flock -n 9 || { echo '已有另一个 PHP2Shell 修复任务在运行。' >&2; exit 1; }
fi

exec > >(tee -a "$LOG_FILE") 2>&1
: >"$REPORT_FILE"
: >"$PLAN_FILE"
: >"$BT_BACKUPS"
: >"$DOCKER_BACKUPS"
: >"$DOCKER_FILES"
: >"$DOCKER_STOPPED"

log() { printf '[%s] %s\n' "$(date '+%F %T')" "$*" | tee -a "$REPORT_FILE"; }
plan() { printf '%s\n' "$*" | tee -a "$PLAN_FILE"; }
die() { log "失败：$*"; log "日志：$LOG_FILE"; exit 1; }

confirm_phrase() {
  local expected="$1" prompt="$2" answer=''
  printf '\n%s\n请输入 %s 继续：' "$prompt" "$expected" >/dev/tty
  IFS= read -r answer </dev/tty || die '交互确认失败。'
  [ "$answer" = "$expected" ] || die '确认口令不匹配，已停止。'
}

version_lt() {
  [ "$1" != "$2" ] && [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)" = "$1" ]
}

official_fixed_for() {
  case "$1" in
    8.2) echo '8.2.35' ;;
    8.3) echo '8.3.36' ;;
    8.4) echo '8.4.27' ;;
    8.5) echo '8.5.12' ;;
    *) echo '' ;;
  esac
}

bt_fixed_for_key() {
  case "$1" in
    74) echo '7.4.34' ;;
    80) echo '8.0.27' ;;
    81) echo '8.1.35' ;;
    82) echo '8.2.35' ;;
    83) echo '8.3.36' ;;
    84) echo '8.4.27' ;;
    85) echo '8.5.12' ;;
    *) echo '' ;;
  esac
}

classify_version() {
  local version="$1" branch fixed
  branch="$(printf '%s' "$version" | awk -F. '{print $1 "." $2}')"
  fixed="$(official_fixed_for "$branch")"
  if [ -n "$fixed" ]; then
    if version_lt "$version" "$fixed"; then
      printf 'vulnerable\t%s\n' "$fixed"
    else
      printf 'fixed\t%s\n' "$fixed"
    fi
    return
  fi
  case "$branch" in
    8.6) printf 'review\t\n' ;;
    *) printf 'eol\t\n' ;;
  esac
}

php_version_bin() {
  local bin="$1"
  "$bin" -v 2>&1 | awk '/^PHP [0-9]/{print $2; exit}'
}

modules_bin() {
  local bin="$1"
  "$bin" -r 'echo implode(PHP_EOL, array_unique(array_merge(get_loaded_extensions(false), get_loaded_extensions(true)))), PHP_EOL;' 2>/dev/null |
    sort
}

oom_security_test() {
  local bin="$1" out="$2" marker="${2}.marker" test_file="${2}.php" rc
  rm -f "$marker" "$out" "$test_file"
  cat >"$test_file" <<'PHP'
<?php
$marker = $argv[1];
register_shutdown_function(function () use ($marker) {
    file_put_contents($marker, "shutdown-ran\n");
});
str_repeat("A", 8 * 1024 * 1024);
PHP
  set +e
  "$bin" -n -d display_errors=1 -d log_errors=0 -d memory_limit=4M "$test_file" "$marker" >"$out" 2>&1
  rc=$?
  set -e
  if [ -s "$marker" ]; then return 1; fi
  [ "$rc" -ne 0 ] || return 1
  grep -qi 'Allowed memory size' "$out"
}

service_for_key() {
  local key="$1"
  if [ -x "/etc/init.d/php-fpm-${key}" ]; then
    echo "/etc/init.d/php-fpm-${key}"
  elif systemctl list-unit-files "php${key}-php-fpm.service" "php-fpm-${key}.service" 2>/dev/null | grep -qE "php(${key}|-fpm-${key})"; then
    systemctl list-unit-files "php${key}-php-fpm.service" "php-fpm-${key}.service" 2>/dev/null |
      awk '/\.service/{print $1; exit}'
  else
    echo ''
  fi
}

service_running() {
  local svc="$1" key="$2"
  [ -n "$svc" ] || return 1
  case "$svc" in
    /etc/init.d/*) "$svc" status >/dev/null 2>&1 ;;
    *) systemctl is-active --quiet "$svc" ;;
  esac && return 0
  ps -eo args= 2>/dev/null | grep -F "/www/server/php/${key}/sbin/php-fpm" | grep -v '[g]rep' >/dev/null 2>&1
}

service_restart() {
  local svc="$1"
  [ -n "$svc" ] || return 1
  case "$svc" in
    /etc/init.d/*) "$svc" restart ;;
    *) systemctl restart "$svc" ;;
  esac
}

service_stop() {
  local svc="$1"
  [ -n "$svc" ] || return 0
  case "$svc" in
    /etc/init.d/*) "$svc" stop >/dev/null 2>&1 || true ;;
    *) systemctl stop "$svc" >/dev/null 2>&1 || true ;;
  esac
}

service_start() {
  local svc="$1"
  [ -n "$svc" ] || return 1
  case "$svc" in
    /etc/init.d/*) "$svc" start ;;
    *) systemctl start "$svc" ;;
  esac
}

http_health() {
  local failures=0 url code
  for url in "${HTTP_URLS[@]}"; do
    code="$(curl -k -sS --connect-timeout 10 --max-time 30 -o /dev/null -w '%{http_code}' "$url" 2>/dev/null || true)"
    log "HTTP 健康检查：$url -> ${code:-000}"
    case "$code" in 2*|3*|4*) ;; *) failures=$((failures+1)) ;; esac
  done
  [ "$failures" -eq 0 ]
}

snapshot_global() {
  {
    echo "time=$(date '+%F %T %z')"
    echo "host=$(hostname -f 2>/dev/null || hostname)"
    echo "kernel=$(uname -a)"
    [ -r /etc/os-release ] && grep -E '^(PRETTY_NAME|VERSION_ID)=' /etc/os-release
    command -v bt >/dev/null 2>&1 && echo 'panel=bt'
  } >"${WORK_DIR}/before.txt"
  ps -eo user,pid,ppid,lstart,args >"${WORK_DIR}/processes-before.txt" 2>&1 || true
  ss -ltnp >"${WORK_DIR}/listen-before.txt" 2>&1 || true
  if command -v docker >/dev/null 2>&1; then
    docker ps -a --no-trunc >"${WORK_DIR}/docker-ps-before.txt" 2>&1 || true
  fi
}

BT_KEYS=()
BT_DIRS=()
BT_VERSIONS=()
BT_STATES=()
BT_FIXED=()
BT_SERVICES=()
BT_NEEDS_ACTION=()

scan_bt() {
  [ "$DO_BT" -eq 1 ] || return 0
  local dir key bin version state fixed svc needs
  for dir in /www/server/php/[0-9]*; do
    [ -d "$dir" ] || continue
    key="$(basename "$dir")"
    bin="${dir}/bin/php"
    [ -x "$bin" ] || continue
    version="$(php_version_bin "$bin" || true)"
    [ -n "$version" ] || continue
    fixed="$(bt_fixed_for_key "$key")"
    if [ -n "$fixed" ] && [ "$version" = "$fixed" ]; then
      state='fixed'
    elif [ -n "$fixed" ]; then
      state='vulnerable'
    else
      state='manual'
    fi
    svc="$(service_for_key "$key")"
    needs=0
    if [ "$state" = 'vulnerable' ] && [ -n "$fixed" ]; then needs=1; fi
    BT_KEYS+=("$key")
    BT_DIRS+=("$dir")
    BT_VERSIONS+=("$version")
    BT_STATES+=("$state")
    BT_FIXED+=("$fixed")
    BT_SERVICES+=("$svc")
    BT_NEEDS_ACTION+=("$needs")
    log "宝塔 PHP ${key}: ${version}，状态=${state}，目标=${fixed:-需人工升级}，服务=${svc:-未找到}"
    if [ "$state" = 'vulnerable' ]; then
      plan "BT\t${key}\t${dir}\t${version}\t${fixed}\t${svc}"
    fi
  done
}

declare -A SEEN_BIN=()
NON_BT_ROWS="${WORK_DIR}/non-bt.tsv"
: >"$NON_BT_ROWS"

scan_non_bt() {
  local bin real version state fixed kind
  {
    command -v php 2>/dev/null || true
    command -v php-fpm 2>/dev/null || true
    command -v php-cgi 2>/dev/null || true
    find /usr/local /opt -maxdepth 5 -type f \( -name php -o -name php-fpm -o -name php-cgi \) 2>/dev/null || true
  } | sort -u | while IFS= read -r bin; do
    [ -x "$bin" ] || continue
    real="$(readlink -f "$bin" 2>/dev/null || printf '%s' "$bin")"
    case "$real" in /www/server/php/*) continue ;; esac
    [ -z "${SEEN_BIN[$real]:-}" ] || continue
    SEEN_BIN[$real]=1
    version="$(php_version_bin "$bin" || true)"
    [ -n "$version" ] || continue
    IFS=$'\t' read -r state fixed <<EOF
$(classify_version "$version")
EOF
    case "$real" in *php-fpm*) kind='fpm' ;; *php-cgi*) kind='cgi' ;; */php) kind='cli' ;; *) kind='other' ;; esac
    printf '%s\t%s\t%s\t%s\t%s\n' "$real" "$version" "$state" "$fixed" "$kind" >>"$NON_BT_ROWS"
    log "非宝塔 PHP：${real}，版本=${version}，状态=${state}，类型=${kind}"
    if [ "$state" != 'fixed' ]; then
      plan "MANUAL_BIN\t${real}\t${version}\t${fixed:-无上游稳定修复}"
    fi
  done
}

DOCKER_IDS=()
DOCKER_NAMES=()
DOCKER_IMAGES=()
DOCKER_VERSIONS=()
DOCKER_PHP_PATHS=()
DOCKER_VARIANTS=()
DOCKER_STATES=()
DOCKER_FIXEDS=()
DOCKER_AUTO=()
DOCKER_OSCODES=()

scan_docker() {
  [ "$DO_DOCKER" -eq 1 ] || return 0
  command -v docker >/dev/null 2>&1 || return 0
  local id name image version path variant state fixed auto mods osid code
  while IFS='|' read -r id name image; do
    [ -n "$id" ] || continue
    version="$(docker exec "$id" php -v 2>/dev/null | awk '/^PHP [0-9]/{print $2; exit}' || true)"
    [ -n "$version" ] || continue
    path="$(docker exec "$id" sh -lc 'command -v php' 2>/dev/null || true)"
    mods="$(docker exec "$id" sh -lc 'apache2ctl -M 2>/dev/null || httpd -M 2>/dev/null' 2>/dev/null || true)"
    if printf '%s' "$mods" | grep -q 'php.*module'; then
      variant='apache'
    elif docker exec "$id" sh -lc 'command -v php-fpm >/dev/null 2>&1' 2>/dev/null; then
      variant='fpm'
    else
      variant='cli'
    fi
    IFS=$'\t' read -r state fixed <<EOF
$(classify_version "$version")
EOF
    auto=0
    osid="$(docker exec "$id" sh -lc ". /etc/os-release 2>/dev/null && echo \$ID" 2>/dev/null || true)"
    code="$(docker exec "$id" sh -lc ". /etc/os-release 2>/dev/null && echo \$VERSION_CODENAME" 2>/dev/null || true)"
    if [ "$state" = 'vulnerable' ] && [ "$path" = '/usr/local/bin/php' ] && [ "$osid" = 'debian' ] && { [ "$code" = 'bookworm' ] || [ "$code" = 'trixie' ]; }; then
      auto=1
    fi
    DOCKER_IDS+=("$id"); DOCKER_NAMES+=("$name"); DOCKER_IMAGES+=("$image")
    DOCKER_VERSIONS+=("$version"); DOCKER_PHP_PATHS+=("$path")
    DOCKER_VARIANTS+=("$variant"); DOCKER_STATES+=("$state")
    DOCKER_FIXEDS+=("$fixed"); DOCKER_AUTO+=("$auto"); DOCKER_OSCODES+=("$code")
    log "Docker ${name}: ${image}，PHP=${version}，SAPI=${variant}，状态=${state}，自动修复=${auto}"
    if [ "$state" = 'vulnerable' ]; then
      plan "DOCKER\t${name}\t${image}\t${version}\t${fixed}\t${variant}\tauto=${auto}"
    fi
  done < <(docker ps --format '{{.ID}}|{{.Names}}|{{.Image}}' 2>/dev/null | head -n 30)
}

ensure_disk_for_backup() {
  local source="$1" avail_kb source_mb required_kb
  source_mb="$(du -sm "$source" 2>/dev/null | awk '{print $1}')"
  avail_kb="$(df -Pk "$WORK_ROOT" | awk 'NR==2{print $4}')"
  required_kb="$((source_mb * 2048 + 1048576))"
  [ "$avail_kb" -ge "$required_kb" ] || die "磁盘不足：备份 $source 至少需要 $((required_kb/1024)) MiB，可用 $((avail_kb/1024)) MiB。"
}

backup_bt_dir() {
  local key="$1" dir="$2" parent out
  parent="$(dirname "$dir")"
  out="${WORK_DIR}/bt-${key}-before-${STAMP}.tar.gz"
  ensure_disk_for_backup "$dir"
  log "备份宝塔 PHP ${key}：$dir -> $out"
  tar --numeric-owner --exclude="${key}/src" --exclude="${key}/src.tar.gz" -C "$parent" -czf "$out" "$key"
  [ -s "$out" ] || die "PHP ${key} 备份为空。"
  sha256sum "$out" >"${out}.sha256"
  printf '%s\t%s\t%s\t%s\t%s\n' "$key" "$dir" "$out" "$(service_for_key "$key")" "$(service_running "$(service_for_key "$key")" "$key" && echo 1 || echo 0)" >>"$BT_BACKUPS"
}

backup_docker_runtime() {
  local id="$1" name="$2" version="$3" fixed="$4" variant="$5" code="$6"
  local dir path target_file target_image avail_kb backup_image
  dir="${WORK_DIR}/docker-${name}-${version}"
  mkdir -p "$dir/files"
  avail_kb="$(df -Pk "$WORK_ROOT" | awk 'NR==2{print $4}')"
  [ "$avail_kb" -ge 2097152 ] || die 'Docker 备份至少需要 2 GiB 可用空间。'
  docker inspect "$id" >"${dir}/inspect.json"
  docker commit "$id" "php2shell-backup:${id}-${STAMP}" >"${dir}/backup-image.txt"
  backup_image="$(tail -n1 "${dir}/backup-image.txt")"
  for path in /usr/local/bin/php /usr/local/sbin/php-fpm /usr/lib/apache2/modules/libphp.so; do
    if docker exec "$id" test -e "$path" 2>/dev/null; then
      target_file="${dir}/files/$(printf '%s' "$path" | sed 's#^/##; s#/#__#g')"
      docker cp "${id}:${path}" "$target_file"
      printf '%s\t%s\t%s\n' "$name" "$path" "$target_file" >>"$DOCKER_FILES"
    fi
  done
  case "$variant" in
    apache) target_image="php:${fixed}-apache-${code}" ;;
    fpm) target_image="php:${fixed}-fpm-${code}" ;;
    *) target_image="php:${fixed}-cli-${code}" ;;
  esac
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$id" "$name" "$version" "$fixed" "$variant" "$backup_image" "$dir" >>"$DOCKER_BACKUPS"
  printf '%s\n' "$target_image" >"${dir}/target-image.txt"
}

write_rollback_script() {
  cat >"$ROLLBACK_SCRIPT" <<'ROLLBACK'
#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
WORK_DIR="$(cd "$(dirname "$0")" && pwd)"
echo '============================================================'
echo 'PHP2Shell 回滚'
echo '将恢复本脚本记录的宝塔 PHP 目录和 Docker PHP 二进制。'
echo '数据库、业务代码和应用数据不在自动回滚范围内。'
echo '============================================================'
read -r -p '输入 ROLLBACK 继续：' confirm
[ "$confirm" = 'ROLLBACK' ] || { echo '已取消。'; exit 1; }

if [ -s "${WORK_DIR}/bt-backups.tsv" ]; then
  while IFS=$'\t' read -r key dir backup svc was_running; do
    [ -n "$key" ] || continue
    echo "[BT ${key}] 停止服务并回滚 $dir"
    if [ -n "$svc" ]; then
      case "$svc" in /etc/init.d/*) "$svc" stop >/dev/null 2>&1 || true ;; *) systemctl stop "$svc" >/dev/null 2>&1 || true ;; esac
    fi
    failed="${dir}.failed-$(date +%Y%m%d-%H%M%S)"
    [ -e "$failed" ] && { echo "失败目录已存在：$failed"; exit 1; }
    [ -d "$dir" ] && mv "$dir" "$failed"
    tar -xzf "$backup" -C "$(dirname "$dir")"
    if [ "$was_running" = 1 ] && [ -n "$svc" ]; then
      case "$svc" in /etc/init.d/*) "$svc" start >/dev/null 2>&1 || true ;; *) systemctl start "$svc" >/dev/null 2>&1 || true ;; esac
    fi
  done <"${WORK_DIR}/bt-backups.tsv"
fi

if [ -s "${WORK_DIR}/docker-backups.tsv" ]; then
  while IFS=$'\t' read -r id name old_version fixed variant backup_image backup_dir; do
    [ -n "$id" ] || continue
    echo "[Docker ${name}] 恢复 PHP 二进制并重启容器"
    docker stop "$id" >/dev/null 2>&1 || true
    while IFS=$'\t' read -r file_container original local_file; do
      [ "$file_container" = "$name" ] || continue
      docker cp "$local_file" "${id}:${original}"
    done <"${WORK_DIR}/docker-files.tsv"
    docker start "$id" >/dev/null 2>&1 || true
  done <"${WORK_DIR}/docker-backups.tsv"
fi

if [ -s "${WORK_DIR}/docker-stopped.tsv" ]; then
  while IFS=$'\t' read -r id name; do
    [ -n "$id" ] || continue
    echo "[Docker ${name}] 重新启动原本无法自动修复、仅被隔离的容器"
    docker start "$id" >/dev/null 2>&1 || true
  done <"${WORK_DIR}/docker-stopped.tsv"
fi

echo '回滚已执行。请立即检查 PHP 版本、网站和日志。'
ROLLBACK
  chmod 700 "$ROLLBACK_SCRIPT"
}

verify_bt_after() {
  local key dir target version modules_before modules_after svc bin fpm
  key="$1"; dir="$2"; target="$3"; svc="$4"
  bin="${dir}/bin/php"; fpm="${dir}/sbin/php-fpm"
  version="$(php_version_bin "$bin" || true)"
  [ "$version" = "$target" ] || { log "PHP ${key} CLI 版本 ${version:-未知} != ${target}"; return 1; }
  "$fpm" -v 2>&1 | grep -q "PHP ${target} " || { log "PHP ${key} FPM 版本不匹配。"; return 1; }
  "$fpm" -t -c "${dir}/etc/php.ini" -y "${dir}/etc/php-fpm.conf" >/dev/null 2>&1 || { log "PHP ${key} FPM 配置测试失败。"; return 1; }
  if [ -f "${dir}/src/main/rfc1867.c" ]; then
    grep -q 'max_multipart_body_parts' "${dir}/src/main/rfc1867.c" || { log "PHP ${key} 源码缺少 multipart 数量限制修复标记。"; return 1; }
  else
    log "PHP ${key} 升级后未保留源码树，跳过源码标记检查；继续执行运行时验证。" "WARN"
  fi
  modules_before="${WORK_DIR}/modules-before-${key}.txt"
  modules_after="${WORK_DIR}/modules-after-${key}.txt"
  modules_bin "$bin" >"$modules_after"
  comm -23 "$modules_before" "$modules_after" >"${WORK_DIR}/modules-missing-${key}.txt"
  [ ! -s "${WORK_DIR}/modules-missing-${key}.txt" ] || { log "PHP ${key} 升级后模块减少。"; return 1; }
  case "$key" in
    74|80|81)
      oom_security_test "$bin" "${WORK_DIR}/oom-after-${key}.txt" || { log "PHP ${key} OOM 安全行为验证失败。"; return 1; }
      ;;
    *)
      # 8.2+ 官方修复改变了 OOM 的退出方式，不把旧 7.4 的 shutdown 标记测试当作硬条件。
      if oom_security_test "$bin" "${WORK_DIR}/oom-after-${key}.txt"; then
        log "PHP ${key} OOM 采样：shutdown function 未执行。"
      else
        log "PHP ${key} OOM 采样：shutdown function 被执行；以官方版本、源码标记、模块和业务验证为准。" "WARN"
      fi
      ;;
  esac
  return 0
}

rollback_bt_component() {
  local key="$1" dir="$2" svc="$3" backup="${WORK_DIR}/bt-${1}-before-${STAMP}.tar.gz" failed
  service_stop "$svc"
  failed="${dir}.failed-${STAMP}"
  [ ! -e "$failed" ] || return 1
  [ -d "$dir" ] && mv "$dir" "$failed"
  tar -xzf "$backup" -C "$(dirname "$dir")" || return 1
  service_start "$svc" || true
  log "已回滚 PHP ${key}。失败版本保留：$failed"
}

apply_bt() {
  local i key dir version target svc bin modules_before updater
  local has_actions=0
  for i in "${!BT_KEYS[@]}"; do [ "${BT_NEEDS_ACTION[$i]}" = 1 ] && has_actions=1; done
  [ "$has_actions" -eq 1 ] || return 0

  updater="${WORK_DIR}/bt-php.sh"
  log '下载并校验宝塔官方 PHP 更新脚本。'
  curl -fsSL --proto '=https' --tlsv1.2 --connect-timeout 15 --max-time 120 -o "$updater" "$BT_UPDATER_URL" || die '下载宝塔更新脚本失败。'
  [ "$(sha256sum "$updater" | awk '{print $1}')" = "$BT_UPDATER_SHA256" ] || die '宝塔更新脚本 SHA256 不匹配，拒绝执行。'
  for i in "${!BT_KEYS[@]}"; do
    key="${BT_KEYS[$i]}"
    target="${BT_FIXED[$i]}"
    [ -n "$target" ] || continue
    grep -Eq "^php_${key}=['\"]${target}['\"]" "$updater" || die "宝塔更新脚本未声明 php_${key}=${target}。"
  done

  for i in "${!BT_KEYS[@]}"; do
    [ "${BT_NEEDS_ACTION[$i]}" = 1 ] || continue
    key="${BT_KEYS[$i]}"; dir="${BT_DIRS[$i]}"; version="${BT_VERSIONS[$i]}"
    target="${BT_FIXED[$i]}"; svc="${BT_SERVICES[$i]}"; bin="${dir}/bin/php"
    log "开始升级宝塔 PHP ${key}: ${version} -> ${target}"
    set +e
    bash "$updater" update "${version%.*}" 9>&- 2>&1 | tee "${WORK_DIR}/bt-update-${key}.log"
    rc=${PIPESTATUS[0]}
    set -e
    if [ "$rc" -ne 0 ]; then
      rollback_bt_component "$key" "$dir" "$svc" || true
      die "宝塔 PHP ${key} 更新失败，已尝试回滚。"
    fi
    if [ -n "$svc" ] && ! service_running "$svc" "$key"; then
      rollback_bt_component "$key" "$dir" "$svc" || true
      die "宝塔 PHP ${key} 更新后服务未运行，已尝试回滚。"
    fi
    if [ -n "$svc" ]; then
      service_restart "$svc" || {
        rollback_bt_component "$key" "$dir" "$svc" || true
        die "宝塔 PHP ${key} 服务重启失败，已尝试回滚。"
      }
    fi
    if ! verify_bt_after "$key" "$dir" "$target" "$svc"; then
      rollback_bt_component "$key" "$dir" "$svc" || true
      die "宝塔 PHP ${key} 升级验证失败，已尝试回滚。"
    fi
    log "宝塔 PHP ${key} 升级并验证通过。"
  done
}

apply_docker() {
  local i id name image version fixed variant auto target_image temp_name old_files_dir osid arch target_osid target_arch stage rc
  for i in "${!DOCKER_IDS[@]}"; do
    [ "${DOCKER_STATES[$i]}" = 'vulnerable' ] || continue
    id="${DOCKER_IDS[$i]}"; name="${DOCKER_NAMES[$i]}"; image="${DOCKER_IMAGES[$i]}"
    version="${DOCKER_VERSIONS[$i]}"; fixed="${DOCKER_FIXEDS[$i]}"; variant="${DOCKER_VARIANTS[$i]}"; auto="${DOCKER_AUTO[$i]}"
    if [ "$auto" != 1 ]; then
      log "Docker ${name} 的 PHP ${version} 不为支持的官方 Debian 运行时，跳过自动覆盖。"
      if [ "$STOP_UNFIXABLE" -eq 1 ]; then
        docker stop "$id" >/dev/null 2>&1 || true
        printf '%s\t%s\n' "$id" "$name" >>"$DOCKER_STOPPED"
        log "已按要求停止无法自动修复的容器 ${name}；回滚可 docker start ${name}。"
      fi
      continue
    fi
    target_image="$(cat "${WORK_DIR}/docker-${name}-${version}/target-image.txt")"
    log "拉取修复运行时 ${target_image}"
    docker pull "$target_image" || die "拉取 ${target_image} 失败。"
    temp_name="php2shell-target-${STAMP}-${i}"
    docker create --name "$temp_name" "$target_image" >/dev/null
    target_osid="$(docker run --rm --entrypoint sh "$target_image" -lc '. /etc/os-release 2>/dev/null && echo $ID' 2>/dev/null || true)"
    target_arch="$(docker run --rm --entrypoint sh "$target_image" -lc 'uname -m' 2>/dev/null || true)"
    osid="$(docker exec "$id" sh -lc '. /etc/os-release 2>/dev/null && echo $ID' 2>/dev/null || true)"
    arch="$(docker exec "$id" sh -lc 'uname -m' 2>/dev/null || true)"
    if [ "$osid" != "$target_osid" ] || [ "$arch" != "$target_arch" ]; then
      docker rm -f "$temp_name" >/dev/null 2>&1 || true
      die "Docker ${name} 与目标 PHP 运行时 OS/架构不一致，已停止自动修复。"
    fi
    docker stop "$id" >/dev/null || die "停止 Docker ${name} 失败。"
    for path in /usr/local/bin/php /usr/local/sbin/php-fpm /usr/lib/apache2/modules/libphp.so; do
      stage="${WORK_DIR}/new-runtime-$(basename "$path")"
      if printf '%s\n' "$(while IFS=$'\t' read -r file_container original local_file; do [ "$file_container" = "$name" ] && [ "$original" = "$path" ] && printf 'yes\n'; done <"$DOCKER_FILES")" | grep -q yes; then
        if ! docker cp "${temp_name}:${path}" "$stage" 2>/dev/null || ! docker cp "$stage" "${id}:${path}"; then
          while IFS=$'\t' read -r file_container original local_file; do
            [ "$file_container" = "$name" ] || continue
            docker cp "$local_file" "${id}:${original}" >/dev/null 2>&1 || true
          done <"$DOCKER_FILES"
          docker start "$id" >/dev/null 2>&1 || true
          docker rm -f "$temp_name" >/dev/null 2>&1 || true
          die "写入容器 ${name}:${path} 失败，已恢复旧文件。"
        fi
      fi
    done
    docker rm -f "$temp_name" >/dev/null 2>&1 || true
    docker start "$id" >/dev/null || die "启动 Docker ${name} 失败。"
    sleep 4
    if [ "$(docker exec "$id" php -v 2>/dev/null | awk '/^PHP [0-9]/{print $2; exit}')" != "$fixed" ]; then
      docker stop "$id" >/dev/null 2>&1 || true
      while IFS=$'\t' read -r file_container original local_file; do
        [ "$file_container" = "$name" ] || continue
        docker cp "$local_file" "${id}:${original}" >/dev/null
      done <"$DOCKER_FILES"
      docker start "$id" >/dev/null 2>&1 || true
      die "Docker ${name} 升级验证失败，已尝试恢复旧 PHP 二进制。"
    fi
    if [ "$variant" = 'fpm' ] && ! docker exec "$id" sh -lc 'php-fpm -v 2>&1' | grep -q "PHP ${fixed} "; then
      docker stop "$id" >/dev/null 2>&1 || true
      while IFS=$'\t' read -r file_container original local_file; do
        [ "$file_container" = "$name" ] || continue
        docker cp "$local_file" "${id}:${original}" >/dev/null
      done <"$DOCKER_FILES"
      docker start "$id" >/dev/null 2>&1 || true
      die "Docker ${name} PHP-FPM 版本验证失败，已尝试恢复旧文件。"
    fi
    if [ "$variant" = 'apache' ]; then
      docker exec "$id" sh -lc 'apache2ctl -t >/dev/null 2>&1' || {
        docker stop "$id" >/dev/null 2>&1 || true
        while IFS=$'\t' read -r file_container original local_file; do
          [ "$file_container" = "$name" ] || continue
          docker cp "$local_file" "${id}:${original}" >/dev/null
        done <"$DOCKER_FILES"
        docker start "$id" >/dev/null 2>&1 || true
        die "Docker ${name} Apache 配置验证失败，已尝试恢复旧 PHP。"
      }
    fi
    log "Docker ${name} PHP ${version} -> ${fixed} 完成。"
  done
}

require_apply_confirmation() {
  [ "$MODE" = 'apply' ] || return 0
  [ -t 0 ] || [ -c /dev/tty ] || die '--apply 需要交互终端，不允许静默执行高风险修复。'
  cat <<'WARN'

==================== 高风险变更提醒 ====================
本脚本可能下载源码、编译 PHP、替换正在使用的 PHP 二进制并完整重启服务。
升级期间网站可能出现 502、上传失败、登录异常或队列中断。
脚本备份不包含数据库和业务代码，不能替代云厂商整机快照。
如无法接受停机，请立即按 Ctrl+C。
建议回滚方式：云厂商控制台恢复整机快照；或运行本次生成的 rollback.sh。
==========================================================
WARN
  confirm_phrase 'I_UNDERSTAND_THE_RISK' '第一确认：我已理解 PHP 升级与重启风险。'
  confirm_phrase 'I_HAVE_A_FULL_SERVER_SNAPSHOT' '第二确认：我已在云厂商控制台创建整机快照。'
}

show_final_rollback_notice() {
  cat <<EOF

==================== 备份与回滚 ====================
本次工作目录：$WORK_DIR
回滚脚本：$ROLLBACK_SCRIPT
执行回滚：bash "$ROLLBACK_SCRIPT"
宝塔 PHP 备份记录：$BT_BACKUPS
Docker 备份记录：$DOCKER_BACKUPS
完整日志：$LOG_FILE
注意：脚本内回滚不恢复数据库、业务代码或整机其他组件。
推荐同时在云厂商控制台保留整机快照。
=====================================================
EOF
}

print_manual_guidance() {
  if [ -s "$NON_BT_ROWS" ]; then
    log '非宝塔 PHP 人工修复路径：'
    if command -v apt-get >/dev/null 2>&1; then
      log '  Debian/Ubuntu：先确认 Ubuntu CVE/USN 或 Debian DSA 状态为 Fixed，再执行 apt update && apt install --only-upgrade PHP 包；不要只按上游数字猜发行版版本。'
    elif command -v dnf >/dev/null 2>&1; then
      log '  RHEL/Rocky/Alma：用 dnf updateinfo list --security 确认本 CVE 后再更新对应 php 模块；升级后完整重启 php-fpm/httpd/nginx。'
    else
      log '  非标准源码安装：先备份 prefix，使用 php -i 中的 Configure Command 以相同扩展配置编译官方修复版，再验证模块和 FPM 配置。'
    fi
  fi
  if [ "${#DOCKER_IDS[@]}" -gt 0 ]; then
    for i in "${!DOCKER_IDS[@]}"; do
      if [ "${DOCKER_STATES[$i]}" = 'vulnerable' ] && [ "${DOCKER_AUTO[$i]}" != 1 ]; then
        log "  Docker ${DOCKER_NAMES[$i]}：更新基础镜像到包含 PHP ${DOCKER_FIXEDS[$i]} 的新镜像并重建容器；禁止只 docker restart。"
      fi
    done
  fi
}

snapshot_global
log '============================================================'
log 'PHP2Shell Linux 全流程检查/修复'
log "模式：$MODE"
log "漏洞：$CVE1 / $CVE2"
log "工作目录：$WORK_DIR"
log '============================================================'

scan_bt
scan_non_bt
scan_docker

HAS_AUTOMATABLE=0
for i in "${!BT_KEYS[@]}"; do
  [ "${BT_NEEDS_ACTION[$i]}" = 1 ] && HAS_AUTOMATABLE=1
done
for i in "${!DOCKER_IDS[@]}"; do
  [ "${DOCKER_STATES[$i]}" = 'vulnerable' ] && [ "${DOCKER_AUTO[$i]}" = 1 ] && HAS_AUTOMATABLE=1
  if [ "$STOP_UNFIXABLE" -eq 1 ] && [ "${DOCKER_STATES[$i]}" = 'vulnerable' ] && [ "${DOCKER_AUTO[$i]}" != 1 ]; then
    HAS_AUTOMATABLE=1
  fi
done

if [ ! -s "$PLAN_FILE" ]; then
  log '未发现需要自动处理的受支持 PHP 运行时。'
else
  log '发现以下自动/人工处理计划：'
  sed 's/^/  /' "$PLAN_FILE" | tee -a "$REPORT_FILE"
fi
print_manual_guidance

if [ "$MODE" = 'check' ]; then
  echo
  echo '检查完成。默认没有修改任何内容。'
  echo "报告：$REPORT_FILE"
  echo "如确认整机快照和回滚办法，执行：bash $0 --apply"
  exit 0
fi

if [ "$HAS_AUTOMATABLE" -eq 0 ]; then
  log '没有可由本脚本安全自动修复的运行时。'
  log '请按 plan.txt 中的发行版包/非标准源码人工路径处理。未修改任何内容。'
  exit 0
fi

require_apply_confirmation

# 在修改前完成所有备份。任一备份失败则整体停止。
if [ "$DO_BT" -eq 1 ]; then
  for i in "${!BT_KEYS[@]}"; do
    [ "${BT_NEEDS_ACTION[$i]}" = 1 ] || continue
    backup_bt_dir "${BT_KEYS[$i]}" "${BT_DIRS[$i]}"
    modules_bin "${BT_DIRS[$i]}/bin/php" >"${WORK_DIR}/modules-before-${BT_KEYS[$i]}.txt"
  done
fi

if [ "$DO_DOCKER" -eq 1 ]; then
  for i in "${!DOCKER_IDS[@]}"; do
    [ "${DOCKER_STATES[$i]}" = 'vulnerable' ] && [ "${DOCKER_AUTO[$i]}" = 1 ] || continue
    backup_docker_runtime "${DOCKER_IDS[$i]}" "${DOCKER_NAMES[$i]}" "${DOCKER_VERSIONS[$i]}" "${DOCKER_FIXEDS[$i]}" "${DOCKER_VARIANTS[$i]}" "${DOCKER_OSCODES[$i]}"
  done
fi

write_rollback_script
show_final_rollback_notice
confirm_phrase 'I_HAVE_VERIFIED_THE_BACKUP_AND_ROLLBACK' '第三确认：我已看到精确备份路径和回滚脚本，并确认可以回滚。'

apply_bt
apply_docker

if [ "${#HTTP_URLS[@]}" -gt 0 ]; then
  http_health || die 'HTTP 健康检查失败，请立即检查日志并考虑运行 rollback.sh。'
fi

log '============================================================'
log 'PHP2Shell 修复流程完成。'
cat >"${WORK_ROOT}/last-success" <<EOF
time=$(date '+%F %T %z')
host=$(hostname -f 2>/dev/null || hostname)
work_dir=$WORK_DIR
rollback=$ROLLBACK_SCRIPT
log=$LOG_FILE
EOF
chmod 600 "${WORK_ROOT}/last-success"
log "回滚脚本：$ROLLBACK_SCRIPT"
log "详细日志：$LOG_FILE"
log '请继续人工检查：网站登录、上传、支付、数据库、队列、定时任务和错误日志。'
log '============================================================'
