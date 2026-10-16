#!/usr/bin/env bash
# Araucaria VPS Manager v1.0.0-rc1 - for a NEW Ubuntu 22.04 / 24.04 VPS.
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
TARGET="www.google.com"
PROFILE_NAME="USAraucaria"
PROFILE_NAME_OVERRIDDEN="no"
XRAY_PORT=""
SSH_PORT_OVERRIDE=""
F2B_MODE="safe"
DO_UPGRADE="yes"
ASSUME_YES="no"
STEP="предварительная проверка"

say() { printf '\n\033[1;36m[Araucaria]\033[0m %s\n' "$*"; }
warn() { printf '\n\033[1;33m[Внимание]\033[0m %s\n' "$*" >&2; }

banner() {
  printf '\n\033[1;36m%s\n  ARAUCARIA | %s\n%s\033[0m\n' \
    '============================================================' "$1" '============================================================'
}

recovery_hint() {
  printf '\n\033[1;33m[ЧТО ДЕЛАТЬ]\033[0m Этап: %s\n' "$STEP" >&2
  case "$STEP" in
    'предварительная проверка')
      printf '  Проверь: чистая Ubuntu 22.04/24.04, root, systemd, SSH.\n  Если Xray/Araucaria уже установлен, НЕ запускай установщик снова.\n  Проверь: cat /etc/os-release; whoami; ss -ltnp\n' >&2 ;;
    'жёлтое приглашение терминала')
      printf '  Проверь /root/.bashrc и права записи: ls -l /root/.bashrc\n  Цвет не влияет на VPN; после исправления можно продолжить вручную.\n' >&2 ;;
    'обновление пакетов')
      printf '  Проверь сеть/DNS и блокировки apt: apt-get update\n  При незавершённой установке пакетов: dpkg --configure -a\n  Затем выбери повтор действия. НЕ запускай весь install.sh заново.\n' >&2 ;;
    'проверка порта и TLS')
      printf '  Проверь DNS/интернет VPS, доступность REALITY-цели по TLS 1.3.\n  Если сайт недоступен, выбери другое значение --target после безопасной отмены ДО настройки UFW.\n' >&2 ;;
    'настройка файрвола')
      printf '  Сохрани текущую SSH-сессию! Проверь: ufw status verbose\n  Убедись, что SSH-порт разрешён, и исправь проблему UFW до повтора.\n  При потере SSH используй аварийную консоль хостинга.\n' >&2 ;;
    'настройка Fail2ban')
      printf '  Проверь: fail2ban-client -t; systemctl status fail2ban --no-pager -l\n  Журнал: journalctl -u fail2ban -n 40 --no-pager\n  Исправь причину и повтори шаг; SSH-сессию не закрывай.\n' >&2 ;;
    'установка Xray')
      printf '  Проверь доступ к GitHub и свободное место: df -h\n  Проверь: systemctl status xray --no-pager -l\n  После частичной установки НЕ повторяй весь install.sh: сначала проверь результат.\n' >&2 ;;
    'отдельный пользователь Xray'|'установка Araucaria')
      printf '  Проверь системного пользователя и права файлов: id araucaria-xray\n  Проверь: ls -la /usr/local/etc/xray /usr/local/bin/araucaria\n  В случае частичной установки не выполняй полный install.sh повторно.\n' >&2 ;;
    'создание и применение REALITY')
      printf '  Проверь: systemctl status xray --no-pager -l\n  Журнал: journalctl -u xray -n 40 --no-pager\n  Не перезаписывай созданные ключи и конфиг без резервной копии.\n' >&2 ;;
    'автоматические обновления безопасности')
      printf '  Проверь права /etc/apt/apt.conf.d/ и свободное место.\n  Xray уже может работать; проверь araucaria status до исправления.\n' >&2 ;;
    'проверка состояния')
      printf '  Проверь: araucaria status; systemctl status xray fail2ban --no-pager\n  Журналы: journalctl -u xray -n 40 --no-pager\n' >&2 ;;
    *)
      printf '  Проверь вывод выше и README.md; устрани причину перед повтором.\n' >&2 ;;
  esac
  printf '  Не закрывай SSH до проверки повторного входа.\n' >&2
}

die() {
  printf '\n\033[1;31m[ОШИБКА]\033[0m %s\n' "$*" >&2
  recovery_hint
  exit 1
}

on_unexpected_error() {
  local status="$1" line="$2"
  trap - ERR
  printf '\n\033[1;31m[СБОЙ]\033[0m Этап: %s; строка: %s; код завершения: %s\n' \
    "$STEP" "$line" "$status" >&2
  recovery_hint
  exit "$status"
}
trap 'on_unexpected_error "$?" "$LINENO"' ERR

on_interrupted() {
  local code="$1"
  trap - INT TERM
  warn "Установка прервана сигналом; шаг: $STEP. Некоторые изменения уже могут быть применены."
  recovery_hint
  exit "$code"
}
trap 'on_interrupted 130' INT
trap 'on_interrupted 143' TERM

# Retry only operations that can be safely attempted again in THIS process.
# Never silently skip firewall, SSH protection or Xray failures.
retry_command() {
  local action="$1" remedy="$2" exit_code reply
  shift 2
  while true; do
    if "$@"; then
      return 0
    else
      exit_code=$?
    fi
    warn "Не удалось: $action (код $exit_code). Возможная причина: $remedy"
    if [[ "$ASSUME_YES" == 'yes' || ! -t 0 ]]; then
      die "Автоматический пропуск невозможен. Устрани ошибку и проверь частичную установку."
    fi
    recovery_hint
    while true; do
      if ! IFS= read -r -p 'Исправь проблему (можно в другой SSH-сессии). Enter/r — повторить, q — остановиться: ' reply; then
        die 'Ввод прерван. Установка остановлена безопасно.'
      fi
      case "$reply" in
        ''|r|retry) break ;;
        q|quit) die 'Установка остановлена пользователем. Исправь проблему до новой попытки.' ;;
        *) warn 'Введи Enter или r для повтора, q для остановки.' ;;
      esac
    done
  done
}


help() {
  cat <<'EOF'
Araucaria VPS Manager — автоматическая настройка нового VPS.

Использование: bash install.sh [параметры]

  --port N             порт VLESS (по умолчанию случайный 1024-65535)
  --ssh-port N         SSH-порт дополнительно к автоматически найденным
  --target HOST        SNI/REALITY-цель (по умолчанию www.google.com)
  --name NAME          имя профиля в ссылке (можно русский, пробелы и emoji)
  --strict-fail2ban    2 попытки / 3 минуты / блок на 72 часа (опасно для новичка)
  --no-upgrade         не выполнять apt-get upgrade
  --yes                не задавать интерактивных вопросов
  -h, --help           эта справка

Запускать только на чистой Ubuntu 22.04/24.04 с правами root.
EOF
}

port_valid() { [[ "$1" =~ ^[0-9]+$ ]] && (( 10#$1 >= 1024 && 10#$1 <= 65535 )); }
ssh_port_valid() { [[ "$1" =~ ^[0-9]+$ ]] && (( 10#$1 >= 1 && 10#$1 <= 65535 )); }

while (( $# )); do
  case "$1" in
    --port|--ssh-port|--target|--name)
      (( $# >= 2 )) || die "После $1 необходимо значение."
      case "$1" in
        --port) XRAY_PORT="$2" ;;
        --ssh-port) SSH_PORT_OVERRIDE="$2" ;;
        --target) TARGET="$2" ;;
        --name) PROFILE_NAME="$2"; PROFILE_NAME_OVERRIDDEN="yes" ;;
      esac
      shift 2 ;;
    --strict-fail2ban) F2B_MODE="strict"; shift ;;
    --no-upgrade) DO_UPGRADE="no"; shift ;;
    --yes) ASSUME_YES="yes"; shift ;;
    -h|--help) help; exit 0 ;;
    *) die "Неизвестный параметр: $1 (справка: bash install.sh --help)" ;;
  esac
done

[[ "$(id -u)" -eq 0 ]] || die "Нужны права root (sudo bash install.sh)."
[[ -f "$SCRIPT_DIR/araucaria.py" ]] || die "Не найден araucaria.py рядом с install.sh. Распакуй архив целиком."
# shellcheck source=/dev/null
source /etc/os-release
[[ "${ID:-}" == 'ubuntu' ]] || die 'Поддерживается только Ubuntu.'
case "${VERSION_ID:-}" in
  22.04|24.04) ;;
  *) die "Поддерживаются Ubuntu 22.04 и 24.04. Сейчас: ${VERSION_ID:-неизвестно}." ;;
esac
command -v systemctl >/dev/null || die 'Нужен systemd.'
[[ -d /run/systemd/system ]] || die 'systemd не запущен. Это не обычный VPS с systemd.'
command -v python3 >/dev/null || die 'Не найден python3. Установи: apt-get install python3.'
command -v ss >/dev/null || die 'Не найдена утилита ss. Установи: apt-get install iproute2.'

for existing in /usr/local/bin/xray /etc/systemd/system/xray.service /etc/araucaria/settings.json /usr/local/bin/araucaria /usr/local/bin/vless-link /usr/local/bin/vless-rotate /usr/local/bin/vless-port /usr/local/bin/vless-name; do
  [[ ! -e "$existing" && ! -L "$existing" ]] || die "Обнаружен $existing. Установщик предназначен для чистого VPS и ничего не перезапишет."
done
id araucaria-xray >/dev/null 2>&1 && die 'Пользователь araucaria-xray уже существует. Отмена во избежание конфликта.'

[[ -z "$SSH_PORT_OVERRIDE" ]] || ssh_port_valid "$SSH_PORT_OVERRIDE" || die 'Неправильный SSH-порт.'
[[ "$TARGET" =~ ^[a-zA-Z0-9-]+([.][a-zA-Z0-9-]+)+$ ]] || die 'Некорректный REALITY-домен.'

# Detect both configured SSH listening ports and the port used by the current SSH session.
declare -a SSH_PORTS=()
add_ssh_port() {
  local candidate="$1" p
  ssh_port_valid "$candidate" || return 0
  for p in "${SSH_PORTS[@]+${SSH_PORTS[@]}}"; do
    [[ "$p" == "$candidate" ]] && return 0
  done
  SSH_PORTS+=("$candidate")
}
if command -v sshd >/dev/null 2>&1; then
  while IFS= read -r found; do
    add_ssh_port "$found"
  done < <(sshd -T 2>/dev/null | awk '$1=="port" {print $2}')
elif [[ -x /usr/sbin/sshd ]]; then
  while IFS= read -r found; do
    add_ssh_port "$found"
  done < <(/usr/sbin/sshd -T 2>/dev/null | awk '$1=="port" {print $2}')
fi
if [[ -n "${SSH_CONNECTION:-}" ]]; then
  # SSH_CONNECTION: client-ip client-port server-ip server-port
  add_ssh_port "$(printf '%s\n' "$SSH_CONNECTION" | awk '{print $4}')"
fi
[[ -z "$SSH_PORT_OVERRIDE" ]] || add_ssh_port "$SSH_PORT_OVERRIDE"
(( ${#SSH_PORTS[@]} > 0 )) || die 'SSH-порт не определён. Перезапусти с --ssh-port 22 (или своим портом).'

# One validator for both command-line and interactive input.
validate_profile_name() {
  python3 - "$SCRIPT_DIR" "$1" <<'PY'
import sys
sys.path.insert(0, sys.argv[1])
from araucaria import AraucariaError, validate_name
try:
    print(validate_name(sys.argv[2]))
except AraucariaError as exc:
    print(f'Неправильное имя профиля: {exc}', file=sys.stderr)
    sys.exit(1)
PY
}

if [[ "$ASSUME_YES" == 'no' && "$PROFILE_NAME_OVERRIDDEN" == 'no' ]]; then
  [[ -t 0 ]] || die 'Неинтерактивный терминал: укажи --name "Название" --yes.'
  while true; do
    entered_name=''
    if ! IFS= read -r -p 'Имя VLESS-профиля [USAraucaria] (Enter = оставить): ' entered_name; then
      die 'Ввод названия отменён. Установка ещё не началась.'
    fi
    # A pasted Windows-style newline may leave a trailing carriage return.
    entered_name="${entered_name%$'\r'}"
    proposed_name="${entered_name:-USAraucaria}"
    if valid_name="$(validate_profile_name "$proposed_name")"; then
      PROFILE_NAME="$valid_name"
      break
    fi
    warn 'Попробуй ещё раз. Например, Tarabar. Enter — оставить USAraucaria.'
  done
else
  PROFILE_NAME="$(validate_profile_name "$PROFILE_NAME")" || die 'Имя VLESS-профиля не прошло проверку.'
fi

# Check TCP listeners, currently configured SSH ports, UFW rules, and socket binding.
# For the default mode, use every port from 1024 to 65535, except unavailable ones.
while true; do
  if selected_port="$(python3 - "$SCRIPT_DIR" "$XRAY_PORT" "${SSH_PORTS[@]}" <<'PY'
import shutil
import sys
sys.path.insert(0, sys.argv[1])
from araucaria import (
    AraucariaError, listening_tcp_ports, port_bindable,
    random_available_port, ufw_ports_in_rules, ufw_status, validate_port,
)
try:
    requested = sys.argv[2]
    unavailable = {int(p) for p in sys.argv[3:]}
    unavailable.update(listening_tcp_ports())
    if shutil.which('ufw'):
        unavailable.update(ufw_ports_in_rules(ufw_status()))
    if requested:
        chosen = validate_port(requested)
        if chosen in unavailable or not port_bindable(chosen):
            raise AraucariaError(f'Выбранный порт {chosen}/tcp занят или зарезервирован для SSH/UFW.')
    else:
        chosen = random_available_port(unavailable)
    print(chosen)
except AraucariaError as exc:
    print(f'Ошибка выбора порта: {exc}', file=sys.stderr)
    sys.exit(1)
PY
)"; then
    XRAY_PORT="$selected_port"
    break
  fi
  if [[ "$ASSUME_YES" == 'yes' || ! -t 0 ]]; then
    die 'Не удалось выбрать TCP-порт. Проверь ss -ltnp и ufw status или передай --port НОМЕР.'
  fi
  warn 'Порт занят, недопустим или недоступен. Можно выбрать другой, не перезапуская установщик.'
  if ! IFS= read -r -p 'TCP-порт 1024–65535; Enter — случайный; q — отмена: ' XRAY_PORT; then
    die 'Ввод порта прерван.'
  fi
  case "$XRAY_PORT" in
    q|quit) die 'Выбор порта отменён.' ;;
  esac
done

say 'План установки:'
printf '  Ubuntu:      %s\n  SSH-порты:   %s\n  VLESS порт:  %s/tcp\n  REALITY SNI: %s\n  Имя профиля: %s\n  Fail2ban:    %s\n' \
  "$VERSION_ID" "${SSH_PORTS[*]}" "$XRAY_PORT" "$TARGET" "$PROFILE_NAME" "$F2B_MODE"
warn 'Вход под root и пароль SSH не меняются. Держи текущее SSH-подключение открытым до повторной проверки!'
if [[ "$ASSUME_YES" == 'no' ]]; then
  [[ -t 0 ]] || die 'Нет интерактивного терминала. Для явного согласия используй --yes.'
  while true; do
    if ! IFS= read -r -p 'Продолжить установку? Напиши yes: ' answer; then
      die 'Ввод подтверждения прерван; установка ещё не началась.'
    fi
    case "$answer" in
      yes) break ;;
      no|q|quit) die 'Установка отменена пользователем.' ;;
      *) warn 'Для продолжения введи yes. Для отмены введи no или q.' ;;
    esac
  done
fi

STEP='жёлтое приглашение терминала'
say 'Настраиваем жёлтые имя root и hostname в Bash (Termius/SSH)...'
# Modify root's shell only. Do not delete Ubuntu's original bashrc sections.
# Marker prevents duplicate settings; the change applies to the NEXT shell.
if ! grep -Fq '# >>> Araucaria shell prompt >>>' /root/.bashrc 2>/dev/null; then
  cat >> /root/.bashrc <<'EOF'

# >>> Araucaria shell prompt >>>
# Yellow username + hostname, ordinary directory; interactive Bash only.
case $- in
  *i*) PS1='\[\e[1;33m\]➜ \u@\h\[\e[0m\]:\w\$ ' ;;
esac
# <<< Araucaria shell prompt <<<
EOF
fi

STEP='обновление пакетов'
say 'Обновляем пакеты и ставим необходимые инструменты...'
export DEBIAN_FRONTEND=noninteractive
retry_command 'обновление индексов пакетов' 'нет интернета, ошибка DNS, репозитория или занят apt' apt-get update
if [[ "$DO_UPGRADE" == 'yes' ]]; then
  retry_command 'обновление Ubuntu' 'проблема репозитория, dpkg или недостаточно места' apt-get -y upgrade
fi
retry_command 'установка зависимостей' 'нет связи с репозиторием либо проблемы dpkg/диска' apt-get install -y ca-certificates curl unzip python3 openssl iproute2 ufw fail2ban python3-systemd unattended-upgrades

STEP='проверка порта и TLS'
[[ -z "$(ss -H -ltn "sport = :$XRAY_PORT")" ]] || die "Порт $XRAY_PORT уже занят. Повтори с --port ДРУГОЙ_ПОРТ."
check_reality_tls() {
  local tls_output
  tls_output="$(timeout 12 openssl s_client -connect "$TARGET:443" -servername "$TARGET" -tls1_3 -alpn h2 -brief </dev/null 2>&1)" || {
    printf '%s\n' "$tls_output" >&2
    return 1
  }
  if [[ "$tls_output" != *'TLSv1.3'* || "$tls_output" != *'Verification: OK'* ]]; then
    printf '%s\n' "$tls_output" >&2
    return 1
  fi
}
say "Проверяем, что $TARGET доступен с VPS по TLS 1.3..."
retry_command "проверка TLS 1.3 и сертификата $TARGET" 'нет DNS/интернета, TLS 1.3 или проверка сертификата не прошла' check_reality_tls

STEP='настройка файрвола'
say 'Разрешаем SSH и порт VLESS в UFW...'
for ssh_port in "${SSH_PORTS[@]}"; do
  retry_command "разрешение SSH ${ssh_port}/tcp" 'UFW не смог добавить SSH-правило' ufw allow "${ssh_port}/tcp" comment 'SSH - keep access'
done
retry_command "разрешение VLESS ${XRAY_PORT}/tcp" 'UFW не смог добавить порт Xray' ufw allow "${XRAY_PORT}/tcp" comment 'Araucaria REALITY'
if ufw status | grep -q '^Status: active'; then
  warn 'UFW уже был включён: прежние правила и политика по умолчанию сохраняются. Проверь вручную другие открытые порты.'
else
  retry_command 'политика входящих UFW' 'ошибка настройки файрвола' ufw default deny incoming
  retry_command 'политика исходящих UFW' 'ошибка настройки файрвола' ufw default allow outgoing
  retry_command 'включение UFW' 'ошибка UFW; SSH-правило должно существовать' ufw --force enable
fi
ufw status

STEP='настройка Fail2ban'
say 'Настраиваем Fail2ban для SSH...'
if [[ "$F2B_MODE" == 'strict' ]]; then
  MAXRETRY=2; FINDTIME='3m'; BANTIME='72h'
  warn 'Строгий режим: ошибёшься дважды — твой IP может попасть в бан на 72 часа.'
else
  MAXRETRY=5; FINDTIME='10m'; BANTIME='12h'
fi
# Fail2ban supports port lists as comma-separated values.
SSH_CSV="$(IFS=,; echo "${SSH_PORTS[*]}")"
cat > /etc/fail2ban/jail.d/araucaria-sshd.local <<EOF
[sshd]
enabled = true
port = $SSH_CSV
backend = systemd
maxretry = $MAXRETRY
findtime = $FINDTIME
bantime = $BANTIME
EOF
chmod 644 /etc/fail2ban/jail.d/araucaria-sshd.local
retry_command 'проверка конфигурации Fail2ban' 'синтаксическая ошибка в /etc/fail2ban/jail.d/araucaria-sshd.local' fail2ban-client -t
retry_command 'включение Fail2ban при старте' 'ошибка systemd' systemctl enable fail2ban
retry_command 'перезапуск Fail2ban' 'ошибка systemd или конфигурации службы' systemctl restart fail2ban
wait_fail2ban_ready() {
  local attempt
  say 'Ждём готовности Fail2ban (до 30 секунд)...'
  for (( attempt=1; attempt<=30; attempt++ )); do
    if fail2ban-client ping >/dev/null 2>&1 && fail2ban-client status sshd >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  systemctl status fail2ban --no-pager -l || true
  journalctl -u fail2ban -n 30 --no-pager || true
  return 1
}
retry_command 'ожидание готовности Fail2ban' 'служба ещё стартует либо в её журнале есть ошибка' wait_fail2ban_ready
fail2ban-client status sshd

STEP='установка Xray'
# The official XTLS installer is pinned and checksum-verified. The *Xray core*
# installed by it is the newest non-prerelease from XTLS/Xray-core releases/latest.
# Review and change the pin deliberately when publishing a new Araucaria release.
XRAY_INSTALL_REF='e741a4f56d368afbb9e5be3361b40c4552d3710d'
XRAY_INSTALL_SHA256='7f70c95f6b418da8b4f4883343d602964915e28748993870fd554383afdbe555'
say 'Скачиваем проверенную редакцию официального установщика XTLS/Xray-install...'
INSTALLER="$(mktemp /tmp/araucaria-xray-install-XXXXXXXX.sh)"
cleanup() { rm -f -- "${INSTALLER:-}"; }
trap cleanup EXIT
retry_command 'скачивание официального установщика Xray' 'проверь доступ к raw.githubusercontent.com, DNS и сертификаты' \
  curl --fail --location --silent --show-error --retry 3 --connect-timeout 15 --max-time 120 \
  "https://raw.githubusercontent.com/XTLS/Xray-install/${XRAY_INSTALL_REF}/install-release.sh" \
  --output "$INSTALLER"
[[ -s "$INSTALLER" ]] || die 'Не удалось скачать официальный установщик Xray.'
printf '%s  %s\n' "$XRAY_INSTALL_SHA256" "$INSTALLER" | sha256sum -c - || \
  die 'Контрольная сумма официального установщика Xray не совпала. Запуск запрещён. Проверь соединение и источник файла.'
bash -n "$INSTALLER" || die 'Установщик Xray содержит синтаксическую ошибку; запуск запрещён.'
say 'Устанавливаем последний официальный стабильный выпуск Xray-core (без beta/pre-release)...'
retry_command 'установка Xray-core' 'проверь логи выше, связь с GitHub и df -h; повтор безопасен только после проверки состояния' bash "$INSTALLER" install
command -v xray >/dev/null || die 'Xray отсутствует после работы установщика.'
XRAY_INSTALLED_VERSION="$(xray version | awk 'NR==1 {print $2}')"
[[ "$XRAY_INSTALLED_VERSION" =~ ^[0-9]+[.][0-9]+[.][0-9]+$ ]] || \
  die 'Xray установлен, но его версия не определена. Проверь: xray version.'
say "Официальный стабильный Xray-core: v$XRAY_INSTALLED_VERSION"

STEP='отдельный пользователь Xray'
say 'Создаём пользователя службы (НЕ меняем SSH-пользователя)...'
useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin araucaria-xray
chown root:araucaria-xray /usr/local/etc/xray
chmod 750 /usr/local/etc/xray
install -d -m 0755 /etc/systemd/system/xray.service.d
cat > /etc/systemd/system/xray.service.d/20-araucaria-hardening.conf <<'EOF'
[Service]
User=araucaria-xray
Group=araucaria-xray
AmbientCapabilities=
CapabilityBoundingSet=
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=full
UMask=0077
EOF
retry_command 'перечитывание службы Xray systemd' 'возможна ошибка файла systemd; проверь systemctl cat xray' systemctl daemon-reload

STEP='установка Araucaria'
say 'Ставим araucaria, vless-link, vless-rotate, vless-port и vless-name...'
install -m 0755 "$SCRIPT_DIR/araucaria.py" /usr/local/bin/araucaria
ln -s /usr/local/bin/araucaria /usr/local/bin/vless-link
ln -s /usr/local/bin/araucaria /usr/local/bin/vless-rotate
ln -s /usr/local/bin/araucaria /usr/local/bin/vless-port
ln -s /usr/local/bin/araucaria /usr/local/bin/vless-name

STEP='создание и применение REALITY'
/usr/local/bin/araucaria init --port "$XRAY_PORT" --target "$TARGET" --name "$PROFILE_NAME"

STEP='автоматические обновления безопасности'
say 'Включаем ежедневную установку обновлений безопасности Ubuntu...'
cat > /etc/apt/apt.conf.d/52araucaria-periodic <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF

STEP='проверка состояния'
/usr/local/bin/araucaria status

# An explicit post-install report instead of an unexplained "done" message.
banner 'ЧТО СДЕЛАНО ПРИ УСТАНОВКЕ'
if [[ "$DO_UPGRADE" == 'yes' ]]; then
  printf '  [OK] Ubuntu %s: пакеты обновлены; утилиты установлены\n' "$VERSION_ID"
else
  printf '  [OK] Ubuntu %s: списки пакетов обновлены; upgrade пропущен\n' "$VERSION_ID"
fi
printf '  [OK] UFW: разрешены SSH (%s/tcp) и VLESS (%s/tcp)\n' "${SSH_PORTS[*]}" "$XRAY_PORT"
printf '  [OK] Fail2ban SSH: %s\n' "$([[ "$F2B_MODE" == strict ]] && echo '2 попытки/3 мин -> 72 ч' || echo '5 попыток/10 мин -> 12 ч')"
printf '  [OK] Xray-core: VLESS + REALITY, TCP, Vision\n'
printf '  [OK] SNI: %s; профиль: %s\n' "$TARGET" "$PROFILE_NAME"
printf '  [OK] Xray: отдельный системный пользователь araucaria-xray\n'
printf '  [OK] Автоматические обновления безопасности Ubuntu\n'
printf '  [OK] Генерация ссылок, смена имени, ключей и порта, резервные копии\n'
printf '  [OK] Жёлтое приглашение root в Bash (в новом SSH-сеансе)\n'
printf '  [НЕ МЕНЯЛИ] Пароль SSH и разрешение входа под root\n'
banner 'ГОТОВАЯ ССЫЛКА'
if ! /usr/local/bin/araucaria link; then
  warn 'Сервис работает, но ссылка не сформировалась автоматически. Используй: vless-link --ip ПУБЛИЧНЫЙ_IP_VPS'
fi

# This block is separate so the operator can find the commands at a glance.
/usr/local/bin/araucaria commands
printf 'ВАЖНО: не закрывай текущую SSH-сессию до проверки второго входа!\n'
if [[ -f /var/run/reboot-required ]]; then
  warn 'Ubuntu сообщает, что для обновлений потребуется перезагрузка. Не спеши: сперва проверь SSH-доступ.'
fi
