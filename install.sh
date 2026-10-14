#!/usr/bin/env bash
# Araucaria VPS Manager v0.1 - for a NEW Ubuntu 22.04 / 24.04 VPS.
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
TARGET="www.google.com"
PROFILE_NAME="USAraucaria"
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

  --port N             порт VLESS (по умолчанию случайный 20000-60000)
  --ssh-port N         SSH-порт дополнительно к автоматически найденным
  --target HOST        SNI/REALITY-цель (по умолчанию www.google.com)
  --name NAME          имя профиля в ссылке (по умолчанию USAraucaria)
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
        --name) PROFILE_NAME="$2" ;;
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

for existing in /usr/local/bin/xray /etc/systemd/system/xray.service /etc/araucaria/settings.json /usr/local/bin/araucaria /usr/local/bin/vless-link /usr/local/bin/vless-rotate; do
  [[ ! -e "$existing" && ! -L "$existing" ]] || die "Обнаружен $existing. Установщик предназначен для чистого VPS и ничего не перезапишет."
done
id araucaria-xray >/dev/null 2>&1 && die 'Пользователь araucaria-xray уже существует. Отмена во избежание конфликта.'

[[ -n "$XRAY_PORT" ]] || XRAY_PORT="$(shuf -i 20000-60000 -n 1)"
port_valid "$XRAY_PORT" || die 'Недопустимый порт VLESS. Допустимо 1024-65535.'
[[ -z "$SSH_PORT_OVERRIDE" ]] || ssh_port_valid "$SSH_PORT_OVERRIDE" || die 'Неправильный SSH-порт.'
[[ "$TARGET" =~ ^[a-zA-Z0-9-]+([.][a-zA-Z0-9-]+)+$ ]] || die 'Некорректный REALITY-домен.'
[[ "$PROFILE_NAME" =~ ^[a-zA-Z0-9_-]{1,48}$ ]] || die 'Имя профиля: 1-48 латинских букв, цифр, - или _.'

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

say 'План установки:'
printf '  Ubuntu:      %s\n  SSH-порты:   %s\n  VLESS порт:  %s/tcp\n  REALITY SNI: %s\n  Имя профиля: %s\n  Fail2ban:    %s\n' \
  "$VERSION_ID" "${SSH_PORTS[*]}" "$XRAY_PORT" "$TARGET" "$PROFILE_NAME" "$F2B_MODE"
warn 'Вход под root и пароль SSH не меняются. Держи текущее SSH-подключение открытым до повторной проверки!'
if [[ "$ASSUME_YES" == 'no' ]]; then
  [[ -t 0 ]] || die 'Нет интерактивного терминала. Для явного согласия используй --yes.'
  read -r -p 'Продолжить установку на НОВОМ VPS? Напиши yes: ' answer
  [[ "$answer" == 'yes' ]] || die 'Установка отменена.'
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
say 'Ставим araucaria, vless-link и vless-rotate...'
install -m 0755 "$SCRIPT_DIR/araucaria.py" /usr/local/bin/araucaria
ln -s /usr/local/bin/araucaria /usr/local/bin/vless-link
ln -s /usr/local/bin/araucaria /usr/local/bin/vless-rotate

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
say 'Установка завершена!'
printf '\nКоманды:\n  vless-link       — вывести актуальную ссылку\n  vless-rotate     — сменить UUID, ключи и Short ID\n  araucaria status — проверить службы\n'
printf '\nТекущую SSH-сессию НЕ закрывай, пока не проверишь второй вход!\n'
if [[ -f /var/run/reboot-required ]]; then
  warn 'Ubuntu сообщает, что для обновлений потребуется перезагрузка. Не спеши: сперва проверь SSH-доступ.'
fi
if ! /usr/local/bin/araucaria link; then
  warn 'Сервис работает, но ссылка не сформировалась автоматически. Используй: vless-link --ip ПУБЛИЧНЫЙ_IP_VPS'
fi
