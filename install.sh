#!/usr/bin/env bash
# Araucaria VPS Manager v0.2.0-rc2 - for a NEW Ubuntu 22.04 / 24.04 VPS.
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
die() { printf '\n\033[1;31m[Ошибка]\033[0m %s\n' "$*" >&2; exit 1; }
trap 'warn "Установка прервана (шаг: $STEP, строка: $LINENO). Рабочее SSH-подключение не закрывай. Смотри README.md."' ERR

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

if [[ "$ASSUME_YES" == 'no' && "$PROFILE_NAME_OVERRIDDEN" == 'no' ]]; then
  [[ -t 0 ]] || die 'Неинтерактивный терминал: укажи --name "Название" --yes.'
  read -r -p 'Имя VLESS-профиля [USAraucaria] (Enter = оставить): ' entered_name
  [[ -z "$entered_name" ]] || PROFILE_NAME="$entered_name"
fi

# Use the same Unicode validation for installer and the future `vless-name` command.
PROFILE_NAME="$(python3 - "$SCRIPT_DIR" "$PROFILE_NAME" <<'PY'
import sys
sys.path.insert(0, sys.argv[1])
from araucaria import AraucariaError, validate_name
try:
    print(validate_name(sys.argv[2]))
except AraucariaError as exc:
    print(f'Неправильное имя профиля: {exc}', file=sys.stderr)
    sys.exit(1)
PY
)" || die 'Имя VLESS-профиля не прошло проверку.'

# Check TCP listeners, currently configured SSH ports, UFW rules, and socket binding.
# For the default mode, use every port from 1024 to 65535, except unavailable ones.
XRAY_PORT="$(python3 - "$SCRIPT_DIR" "$XRAY_PORT" "${SSH_PORTS[@]}" <<'PY'
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
)" || die 'Не удалось выбрать безопасный свободный порт VLESS.'

say 'План установки:'
printf '  Ubuntu:      %s\n  SSH-порты:   %s\n  VLESS порт:  %s/tcp\n  REALITY SNI: %s\n  Имя профиля: %s\n  Fail2ban:    %s\n' \
  "$VERSION_ID" "${SSH_PORTS[*]}" "$XRAY_PORT" "$TARGET" "$PROFILE_NAME" "$F2B_MODE"
warn 'Вход под root и пароль SSH не меняются. Держи текущее SSH-подключение открытым до повторной проверки!'
if [[ "$ASSUME_YES" == 'no' ]]; then
  [[ -t 0 ]] || die 'Нет интерактивного терминала. Для явного согласия используй --yes.'
  read -r -p 'Продолжить установку на НОВОМ VPS? Напиши yes: ' answer
  [[ "$answer" == 'yes' ]] || die 'Установка отменена.'
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
apt-get update
if [[ "$DO_UPGRADE" == 'yes' ]]; then
  apt-get -y upgrade
fi
apt-get install -y ca-certificates curl unzip python3 openssl iproute2 ufw fail2ban python3-systemd unattended-upgrades

STEP='проверка порта и TLS'
[[ -z "$(ss -H -ltn "sport = :$XRAY_PORT")" ]] || die "Порт $XRAY_PORT уже занят. Повтори с --port ДРУГОЙ_ПОРТ."
say "Проверяем, что $TARGET доступен с VPS по TLS 1.3..."
TLS_OUTPUT="$(timeout 12 openssl s_client -connect "$TARGET:443" -servername "$TARGET" -tls1_3 -alpn h2 -brief </dev/null 2>&1)" || die "TLS-проверка $TARGET не прошла. Выбери другой --target."
[[ "$TLS_OUTPUT" == *'TLSv1.3'* && "$TLS_OUTPUT" == *'Verification: OK'* ]] || die 'Не удалось подтвердить TLS 1.3 и корректность сертификата REALITY-цели.'

STEP='настройка файрвола'
say 'Разрешаем SSH и порт VLESS в UFW...'
for ssh_port in "${SSH_PORTS[@]}"; do
  ufw allow "${ssh_port}/tcp" comment 'SSH - keep access'
done
ufw allow "${XRAY_PORT}/tcp" comment 'Araucaria REALITY'
if ufw status | grep -q '^Status: active'; then
  warn 'UFW уже был включён: прежние правила и политика по умолчанию сохраняются. Проверь вручную другие открытые порты.'
else
  ufw default deny incoming
  ufw default allow outgoing
  ufw --force enable
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
fail2ban-client -t
# Ubuntu's systemd unit may report "started" before Fail2ban creates its socket.
# Avoid starting and immediately stopping the daemon: restart once and wait.
systemctl enable fail2ban
systemctl restart fail2ban
say 'Ждём готовности Fail2ban (до 30 секунд)...'
F2B_READY='no'
for (( attempt=1; attempt<=30; attempt++ )); do
  if fail2ban-client ping >/dev/null 2>&1 && fail2ban-client status sshd >/dev/null 2>&1; then
    F2B_READY='yes'
    break
  fi
  sleep 1
done
if [[ "$F2B_READY" != 'yes' ]]; then
  warn 'Fail2ban не ответил за 30 секунд. Диагностика:'
  systemctl status fail2ban --no-pager -l || true
  journalctl -u fail2ban -n 30 --no-pager || true
  die 'Fail2ban не готов. Посмотри журнал выше.'
fi
fail2ban-client status sshd

STEP='установка Xray'
say 'Скачиваем официальный установщик XTLS/Xray-install...'
INSTALLER="$(mktemp /tmp/araucaria-xray-install-XXXXXXXX.sh)"
cleanup() { rm -f -- "${INSTALLER:-}"; }
trap cleanup EXIT
curl --fail --location --silent --show-error --retry 3 --connect-timeout 15 --max-time 120 \
  https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh \
  --output "$INSTALLER"
[[ -s "$INSTALLER" ]] || die 'Не удалось скачать установщик Xray.'
bash "$INSTALLER" install
command -v xray >/dev/null || die 'Xray не установлен.'

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
systemctl daemon-reload

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
printf '\n\033[1;36m%s\033[0m\n' '============================================================'
printf '\033[1;36m%s\033[0m\n' '  ARAUCARIA | ЧТО СДЕЛАНО ПРИ УСТАНОВКЕ'
printf '\033[1;36m%s\033[0m\n' '============================================================'
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
printf '%s\n' '------------------------------------------------------------'
printf '\n\033[1;36m%s\033[0m\n' '  ARAUCARIA | ГОТОВАЯ ССЫЛКА'
printf '%s\n' '------------------------------------------------------------'
if ! /usr/local/bin/araucaria link; then
  warn 'Сервис работает, но ссылка не сформировалась автоматически. Используй: vless-link --ip ПУБЛИЧНЫЙ_IP_VPS'
fi

# This block is separate so the operator can find the commands at a glance.
/usr/local/bin/araucaria commands
printf 'ВАЖНО: не закрывай текущую SSH-сессию до проверки второго входа!\n'
printf 'Цвет имени появится после нового входа (или: source /root/.bashrc).\n'
printf 'Новая VLESS-ссылка секретная — не публикуй её.\n'
if [[ -f /var/run/reboot-required ]]; then
  warn 'Ubuntu сообщает, что для обновлений потребуется перезагрузка. Не спеши: сперва проверь SSH-доступ.'
fi
