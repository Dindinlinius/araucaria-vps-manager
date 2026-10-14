#!/usr/bin/env python3
"""Araucaria VPS Manager: configuration, link export and safe credential rotation.

Only Python 3 standard-library modules are used.
"""

import argparse
import contextlib
import copy
import fcntl
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
import unicodedata
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlencode
from urllib.request import urlopen

CONFIG_FILE = Path('/usr/local/etc/xray/config.json')
SETTINGS_FILE = Path('/etc/araucaria/settings.json')
BACKUP_DIR = Path('/var/backups/araucaria')
LOCK_FILE = Path('/run/lock/araucaria.lock')
INBOUND_TAG = 'vless-reality'
SERVICE_USER = 'araucaria-xray'
DEFAULT_NAME = 'USAraucaria'
MIN_USER_PORT = 1024
MAX_USER_PORT = 65535


class AraucariaError(Exception):
    """A user-facing, recoverable error."""


def run(*args, capture=False, check=True):
    return subprocess.run(
        list(args), check=check, text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
    )


def require_root():
    if os.geteuid() != 0:
        raise AraucariaError('Нужны права root. Используй sudo или войди под root.')


def read_json(path):
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except FileNotFoundError:
        raise AraucariaError(f'Не найден файл: {path}')
    except (ValueError, OSError) as exc:
        raise AraucariaError(f'Не могу прочитать JSON {path}: {exc}')


def validate_port(port):
    try:
        candidate = int(port)
    except (TypeError, ValueError):
        raise AraucariaError('Порт должен быть целым числом от 1024 до 65535.')
    if not (MIN_USER_PORT <= candidate <= MAX_USER_PORT):
        raise AraucariaError('Порт должен быть от 1024 до 65535.')
    return candidate


def validate_name(value):
    """Allow readable Unicode profile names, but reject unsafe/invisible controls."""
    if not isinstance(value, str):
        raise AraucariaError('Название VLESS должно быть текстом.')
    if any(unicodedata.category(char) in ('Cc', 'Cf', 'Cs', 'Zl', 'Zp')
           for char in value):
        raise AraucariaError('В названии VLESS нельзя использовать управляющие или невидимые символы.')
    name = unicodedata.normalize('NFC', value).strip()
    if not name or len(name) > 64 or len(name.encode('utf-8')) > 192:
        raise AraucariaError('Название VLESS: от 1 до 64 символов (до 192 байт UTF-8).')
    return name


def validate_target(target):
    """Require an ordinary DNS host; no arbitrary ports, paths or IP literals."""
    if not isinstance(target, str) or len(target) > 253:
        raise AraucariaError('Некорректное имя сайта REALITY.')
    pattern = r'(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}'
    if not re.fullmatch(pattern, target):
        raise AraucariaError('Укажи домен, например www.google.com, без https:// или :443.')
    return target.lower()


def get_x25519_pair():
    try:
        output = run('xray', 'x25519', capture=True).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        raise AraucariaError(f'Xray не смог создать ключи: {exc}')
    match = re.search(r'^PrivateKey:\s*(\S+)', output, re.M)
    if not match:
        raise AraucariaError('В выводе xray x25519 нет PrivateKey.')
    # Validate that Xray can derive the public value before modifying the service.
    get_public_key(match.group(1))
    return match.group(1)


def get_public_key(private_key):
    try:
        output = run('xray', 'x25519', '-i', private_key, capture=True).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        raise AraucariaError(f'Xray не смог вычислить публичный ключ: {exc}')
    match = re.search(r'^(?:Password(?: \(PublicKey\))?|PublicKey):\s*(\S+)', output, re.M)
    if not match:
        raise AraucariaError('В выводе xray x25519 -i не найден PublicKey/Password.')
    return match.group(1)


def find_inbound(config):
    matches = [
        i for i in config.get('inbounds', [])
        if i.get('tag') == INBOUND_TAG
        and i.get('protocol') == 'vless'
        and i.get('streamSettings', {}).get('security') == 'reality'
    ]
    if len(matches) != 1:
        raise AraucariaError('В конфигурации не найден ровно один VLESS + REALITY Araucaria.')
    return matches[0]


def validate_inbound(inbound):
    settings = inbound['settings']
    reality = inbound['streamSettings']['realitySettings']
    if inbound['streamSettings'].get('network', 'tcp') not in ('tcp', 'raw'):
        raise AraucariaError('Генератор ссылок поддерживает TCP/RAW.')
    if len(settings.get('clients', [])) != 1:
        raise AraucariaError('Нужен ровно один VLESS-пользователь для текущей версии.')
    if len(reality.get('shortIds', [])) != 1 or not reality['shortIds'][0]:
        raise AraucariaError('Нужен ровно один непустой Short ID.')
    if len(reality.get('serverNames', [])) != 1:
        raise AraucariaError('Нужен ровно один SNI для текущей версии.')
    return settings['clients'][0], reality


def make_config(port, target):
    return {
        'log': {'loglevel': 'warning'},
        'inbounds': [{
            'tag': INBOUND_TAG,
            'listen': '0.0.0.0',
            'port': validate_port(port),
            'protocol': 'vless',
            'settings': {
                'clients': [{'id': str(uuid.uuid4()), 'flow': 'xtls-rprx-vision'}],
                'decryption': 'none',
            },
            'streamSettings': {
                'network': 'tcp',
                'security': 'reality',
                'realitySettings': {
                    'target': f'{validate_target(target)}:443',
                    'serverNames': [target.lower()],
                    'privateKey': get_x25519_pair(),
                    'shortIds': [secrets.token_hex(8)],
                },
            },
        }],
        'outbounds': [{'tag': 'direct', 'protocol': 'freedom'}],
    }


@contextlib.contextmanager
def exclusive_lock():
    LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
    with LOCK_FILE.open('a+', encoding='utf-8') as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        yield


def save_json_private(path, value, mode=0o600, group_id=None):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, filename = tempfile.mkstemp(prefix='.araucaria-', suffix='.json', dir=str(path.parent))
    temp_path = Path(filename)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as file:
            json.dump(value, file, ensure_ascii=False, indent=2)
            file.write('\n')
            file.flush()
            os.fsync(file.fileno())
        os.chmod(temp_path, mode)
        if group_id is not None:
            os.chown(temp_path, 0, group_id)
        os.replace(temp_path, path)
    finally:
        temp_path.unlink(missing_ok=True)


def xray_group_id():
    import grp
    try:
        return grp.getgrnam(SERVICE_USER).gr_gid
    except KeyError:
        raise AraucariaError(f'Системная группа {SERVICE_USER} не существует.')


def check_xray_config(config_path):
    try:
        result = run('xray', 'run', '-test', '-config', str(config_path), capture=True, check=False)
    except OSError as exc:
        raise AraucariaError(f'Не удалось запустить Xray для проверки: {exc}')
    if result.returncode != 0:
        msg = (result.stderr or result.stdout or 'неизвестная ошибка').strip()
        raise AraucariaError(f'Конфигурация Xray не прошла проверку: {msg[-1600:]}')


def backup_original():
    BACKUP_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(BACKUP_DIR, 0o700)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-%f')
    backup = BACKUP_DIR / f'config-{stamp}.json'
    shutil.copy2(CONFIG_FILE, backup)
    backup.chmod(0o600)
    return backup


def service_ok(port):
    if run('systemctl', 'is-active', '--quiet', 'xray', check=False).returncode != 0:
        return False
    try:
        with socket.create_connection(('127.0.0.1', port), timeout=2):
            return True
    except OSError:
        return False


def apply_config(config):
    """Test candidate, back up existing config and roll back on failed restart."""
    gid = xray_group_id()
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix='config-candidate-', suffix='.json', dir=str(CONFIG_FILE.parent))
    candidate = Path(name)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as file:
            json.dump(config, file, indent=2, ensure_ascii=False)
            file.write('\n')
        os.chown(candidate, 0, gid)
        os.chmod(candidate, 0o640)
        check_xray_config(candidate)
        backup = backup_original()
        os.replace(candidate, CONFIG_FILE)
        try:
            run('systemctl', 'restart', 'xray')
            time.sleep(1)
            if not service_ok(find_inbound(config)['port']):
                raise AraucariaError('Xray не запущен или порт не слушается.')
        except (OSError, subprocess.CalledProcessError, AraucariaError) as exc:
            # Never use the backup as a live config by rename; keep it for recovery.
            restore_fd, restore_path = tempfile.mkstemp(
                prefix='config-restore-', suffix='.json', dir=str(CONFIG_FILE.parent)
            )
            os.close(restore_fd)
            try:
                shutil.copyfile(backup, restore_path)
                os.chown(restore_path, 0, gid)
                os.chmod(restore_path, 0o640)
                os.replace(restore_path, CONFIG_FILE)
                rollback = run('systemctl', 'restart', 'xray', check=False)
            except Exception as rollback_exc:
                raise AraucariaError(
                    f'Новая конфигурация не запустилась: {exc}. '
                    f'Автооткат не удался: {rollback_exc}. Резервная копия: {backup}'
                )
            if rollback.returncode:
                raise AraucariaError(
                    f'Новая конфигурация не запустилась: {exc}. '
                    f'Возврат выполнен, но Xray не поднялся. Копия: {backup}'
                )
            raise AraucariaError(
                f'Новая конфигурация не запустилась: {exc}. '
                f'Прежний файл восстановлен. Копия: {backup}'
            )
        return backup
    finally:
        candidate.unlink(missing_ok=True)


def init(args):
    require_root()
    target = validate_target(args.target)
    profile_name = validate_name(args.name)
    with exclusive_lock():
        previous = read_json(CONFIG_FILE)
        if previous.get('inbounds'):
            raise AraucariaError('В Xray уже есть входящие подключения. Ничего не перезаписываем.')
        if SETTINGS_FILE.exists():
            raise AraucariaError('Настройки Araucaria уже есть. Повторная установка отменена.')
        config = make_config(args.port, target)
        backup = apply_config(config)
        settings = {'name': profile_name, 'created_utc': datetime.now(timezone.utc).isoformat()}
        save_json_private(SETTINGS_FILE, settings)
    print('VLESS + REALITY установлен и работает.')
    print(f'Порт: {args.port}; SNI: {target}; имя: {profile_name}')
    print(f'Резервная копия: {backup}')


def rotate(args):
    require_root()
    with exclusive_lock():
        config = read_json(CONFIG_FILE)
        inbound = find_inbound(config)
        client, reality = validate_inbound(inbound)
        old_uuid = client['id']
        client['id'] = str(uuid.uuid4())
        reality['privateKey'] = get_x25519_pair()
        reality['shortIds'] = [secrets.token_hex(8)]
        backup = apply_config(config)
    print('Ключи, UUID и Short ID обновлены. Прежняя ссылка недействительна.')
    print(f'Резервная копия: {backup}')
    # Never output the old UUID or private key.
    try:
        show_link(args)
    except AraucariaError as exc:
        print(f'Новые параметры применены, но ссылка не выведена: {exc}', file=sys.stderr)
        print('Запусти: vless-link --ip АДРЕС_СЕРВЕРА', file=sys.stderr)


def public_ipv4(explicit=None):
    if explicit:
        candidate = explicit
    else:
        try:
            with urlopen('https://api4.ipify.org', timeout=8) as response:
                candidate = response.read(100).decode('ascii').strip()
        except Exception as exc:
            raise AraucariaError(
                'Не удалось определить публичный IPv4. '
                'Запусти vless-link --ip АДРЕС_СЕРВЕРА. '
                f'Детали: {exc}'
            )
    try:
        parsed = ipaddress.IPv4Address(candidate)
    except ipaddress.AddressValueError:
        raise AraucariaError('Некорректный IPv4 сервера.')
    return str(parsed)


def make_link(config, ip, name=DEFAULT_NAME):
    inbound = find_inbound(config)
    client, reality = validate_inbound(inbound)
    short_id = reality['shortIds'][0]
    if not re.fullmatch(r'(?:[0-9a-fA-F]{2}){1,8}', short_id):
        raise AraucariaError('Short ID должен состоять из 2-16 hex-символов, число символов чётное.')
    params = {
        'encryption': 'none',
        'security': 'reality',
        'type': 'tcp',
        'sni': reality['serverNames'][0],
        'fp': 'chrome',
        'pbk': get_public_key(reality['privateKey']),
        'sid': short_id,
    }
    if client.get('flow'):
        params['flow'] = client['flow']
    return (
        f"vless://{client['id']}@{ip}:{inbound['port']}?"
        f"{urlencode(params)}#{quote(validate_name(name), safe='')}"
    )


def show_link(args):
    config = read_json(CONFIG_FILE)
    settings = read_json(SETTINGS_FILE)
    ip = public_ipv4(args.ip)
    inbound = find_inbound(config)
    client, reality = validate_inbound(inbound)
    profile_name = validate_name(settings.get('name', DEFAULT_NAME))
    link = make_link(config, ip, profile_name)
    print('\n===== ARAUCARIA: VLESS + REALITY =====')
    print(f'IP:   {ip}')
    print(f"Порт: {inbound['port']}")
    print(f"SNI:  {reality['serverNames'][0]}")
    print(f'Имя:  {profile_name}')
    print('\nСсылка (не публикуй её):\n')
    print(link)
    print('\n=====================================\n')


def rename_vless(args):
    """Update only the link display label, without touching Xray or its keys."""
    require_root()
    with exclusive_lock():
        find_inbound(read_json(CONFIG_FILE))
        settings = read_json(SETTINGS_FILE)
        previous = validate_name(settings.get('name', DEFAULT_NAME))

        print('\n' + '=' * 58)
        print('  ARAUCARIA | ПЕРЕИМЕНОВАНИЕ VLESS-СЫЛКИ')
        print('=' * 58)
        print(f'  Текущее имя: {previous}')
        if args.name is None:
            if not sys.stdin.isatty():
                raise AraucariaError('Укажи новое имя: vless-name "Название VPN"')
            try:
                requested = input('  Новое имя (русский, пробелы, до 64 символов): ')
            except EOFError:
                raise AraucariaError('Ввод отменён.')
        else:
            requested = args.name
        new_name = validate_name(requested)

        if new_name == previous:
            print('  Название не изменилось. Настройки сохранены.')
            return
        settings['name'] = new_name
        save_json_private(SETTINGS_FILE, settings)

    print('\n' + '=' * 58)
    print('  НАЗВАНИЕ ССЫЛКИ ОБНОВЛЕНО')
    print('=' * 58)
    print(f'  Было:            {previous}')
    print(f'  Стало:           {new_name}')
    print('  Xray/ключи/порт: без изменений; перезапуск не нужен')
    print('  Важно: переимпортируй ссылку в клиент, чтобы увидеть новое имя.')
    print('=' * 58)
    try:
        show_link(args)
    except AraucariaError as exc:
        print(f'Название сохранено, но ссылка не выведена: {exc}', file=sys.stderr)
        print('Используй: vless-link --ip ПУБЛИЧНЫЙ_IP', file=sys.stderr)


def show_status(args):
    config = read_json(CONFIG_FILE)
    inbound = find_inbound(config)
    print('Araucaria VPS Manager')
    print(f'Xray: {"активен" if service_ok(inbound["port"]) else "не отвечает"}')
    print(f'Порт: {inbound["port"]}')
    print(f"REALITY SNI: {inbound['streamSettings']['realitySettings']['serverNames'][0]}")
    for cmd, label in [(['ufw', 'status'], 'UFW'),
                       (['fail2ban-client', 'status', 'sshd'], 'Fail2ban SSH')]:
        print(f'\n{label}:')
        try:
            subprocess.run(cmd, check=False)
        except OSError:
            print('Команда недоступна')



def listening_tcp_ports():
    """Return TCP LISTEN ports, including listeners bound to IPv6 or loopback."""
    try:
        output = run('ss', '-H', '-ltn', capture=True).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        raise AraucariaError(f'Не удалось прочитать занятые TCP-порты (ss): {exc}')
    ports = set()
    for line in (output or '').splitlines():
        columns = line.split()
        if len(columns) < 4:
            continue
        possible = columns[3].rsplit(':', 1)[-1]
        if possible.isascii() and possible.isdecimal():
            ports.add(int(possible))
    return ports


def port_bindable(port):
    """An additional check, since a new TCP listener may appear after `ss`."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(('0.0.0.0', port))
        return True
    except OSError:
        return False


def ufw_status():
    try:
        result = run('ufw', 'status', capture=True)
        return result.stdout or ''
    except (OSError, subprocess.CalledProcessError) as exc:
        raise AraucariaError(f'Не удалось проверить UFW: {exc}')


def ufw_port_rules(status, port):
    pattern = re.compile(r'^\s*' + re.escape(str(port)) + r'/tcp(?:\s|\()')
    return [line for line in status.splitlines() if pattern.match(line)]


def ufw_ports_in_rules(status):
    return {int(m.group(1)) for line in status.splitlines()
            if (m := re.match(r'^\s*(\d+)/tcp(?:\s|\()', line))}


def ufw_managed_allow(status, port):
    return any('ALLOW' in line and 'Araucaria REALITY' in line
               for line in ufw_port_rules(status, port))


def call_ufw(*args):
    try:
        run('ufw', *args)
    except (OSError, subprocess.CalledProcessError) as exc:
        raise AraucariaError(f'Команда UFW не выполнилась: ufw {" ".join(args)}: {exc}')


def choose_vless_port(args, old_port, unavailable):
    if args.port is not None and args.random:
        raise AraucariaError('Выбери либо конкретный порт, либо --random.')

    print('\n' + '=' * 58)
    print('  ARAUCARIA | СМЕНА ПОРТА VLESS + REALITY')
    print('=' * 58)
    print(f'Текущий порт:      {old_port}/tcp')
    print('Допустимый диапазон: 1024–65535')
    print('Случайный порт:      20000–60000')
    occupied = sorted(listening_tcp_ports())
    shown = ', '.join(map(str, occupied[:35])) or 'нет'
    suffix = f' ... и ещё {len(occupied) - 35}' if len(occupied) > 35 else ''
    print(f'Занятые TCP-порты (LISTEN): {shown}{suffix}')
    print('Занятые правилами UFW порты тоже не будут выбраны.')

    if args.random:
        selection = 'yes'
    elif args.port is not None:
        selection = str(args.port)
    else:
        if not sys.stdin.isatty():
            raise AraucariaError('Нужен терминал. Или укажи: vless-port --random / vless-port 38421')
        try:
            selection = input('\nyes — случайный порт, или введи номер порта: ').strip().lower()
        except EOFError:
            raise AraucariaError('Ввод отменён.')

    if selection == 'yes':
        for _ in range(2000):
            candidate = 20000 + secrets.randbelow(40001)
            if candidate not in unavailable and port_bindable(candidate):
                return candidate
        raise AraucariaError('Не удалось подобрать свободный TCP-порт.')

    if not re.fullmatch(r'[0-9]{1,5}', selection):
        raise AraucariaError('Введи yes либо число от 1024 до 65535.')
    candidate = validate_port(int(selection))
    if candidate == old_port:
        raise AraucariaError('Это уже текущий порт. Ничего менять не нужно.')
    if candidate in unavailable or not port_bindable(candidate):
        raise AraucariaError(f'Порт {candidate} занят или имеет правило UFW. Выбери другой.')
    return candidate


def switch_vless_port(args):
    """Open new firewall port -> switch tested Xray -> close old port.

    On failure, attempt rollback and do not silently abandon a running service.
    """
    require_root()
    with exclusive_lock():
        original = read_json(CONFIG_FILE)
        inbound = find_inbound(original)
        validate_inbound(inbound)
        old_port = int(inbound['port'])
        status = ufw_status()
        if not re.search(r'^Status: active\s*$', status, re.M):
            raise AraucariaError('UFW не активен. Не можем гарантировать безопасную смену порта.')
        if not ufw_managed_allow(status, old_port):
            raise AraucariaError(
                f'Нет правила UFW Araucaria REALITY для старого порта {old_port}. '
                'Сначала проверь ufw status; автоматическое удаление чужих правил запрещено.'
            )

        occupied = listening_tcp_ports()
        forbidden = occupied | ufw_ports_in_rules(status) | {old_port}
        new_port = choose_vless_port(args, old_port, forbidden)

        # No live changes have occurred up to here.
        replacement = copy.deepcopy(original)
        find_inbound(replacement)['port'] = new_port
        print(f'\nПереключаем {old_port}/tcp -> {new_port}/tcp...')

        try:
            call_ufw('allow', f'{new_port}/tcp', 'comment', 'Araucaria REALITY')
        except AraucariaError as exc:
            # Even a failed UFW command may have already added IPv4/IPv6 rules.
            try:
                if ufw_port_rules(ufw_status(), new_port):
                    call_ufw('--force', 'delete', 'allow', f'{new_port}/tcp')
            except AraucariaError as cleanup_exc:
                raise AraucariaError(
                    f'Ошибка открытия нового порта: {exc}. '
                    f'Проверь возможное оставшееся правило {new_port}/tcp: {cleanup_exc}'
                ) from exc
            raise
        try:
            if not ufw_managed_allow(ufw_status(), new_port):
                raise AraucariaError('Новое правило UFW не обнаружено после добавления.')
            backup = apply_config(replacement)
        except Exception as exc:
            try:
                call_ufw('--force', 'delete', 'allow', f'{new_port}/tcp')
            except AraucariaError as cleanup_exc:
                raise AraucariaError(
                    f'Xray не переключился: {exc}. '
                    f'Не удалось удалить новое правило {new_port}/tcp: {cleanup_exc}'
                ) from exc
            raise AraucariaError(f'Переключение Xray отменено, новый порт закрыт: {exc}') from exc

        try:
            call_ufw('--force', 'delete', 'allow', f'{old_port}/tcp')
            if ufw_port_rules(ufw_status(), old_port):
                raise AraucariaError('После удаления старый порт всё ещё присутствует в правилах UFW.')
        except Exception as exc:
            # Restore firewall access to the previous port before restoring Xray.
            try:
                if not ufw_managed_allow(ufw_status(), old_port):
                    call_ufw('allow', f'{old_port}/tcp', 'comment', 'Araucaria REALITY')
                apply_config(original)
            except Exception as rollback_exc:
                raise AraucariaError(
                    f'Не удалось закрыть старый порт: {exc}. '
                    f'АВТОВОССТАНОВЛЕНИЕ НЕ УДАЛОСЬ: {rollback_exc}. '
                    f'Новый порт {new_port}/tcp оставлен открытым; проверь Xray и UFW вручную.'
                ) from exc
            try:
                call_ufw('--force', 'delete', 'allow', f'{new_port}/tcp')
            except AraucariaError as cleanup_exc:
                raise AraucariaError(
                    f'Старый конфиг и порт {old_port}/tcp восстановлены, '
                    f'но новый порт {new_port}/tcp не удалось закрыть: {cleanup_exc}'
                ) from exc
            raise AraucariaError(
                f'Не удалось закрыть старый порт ({exc}). '
                'Предыдущее подключение восстановлено; выбери другой порт или проверь UFW.'
            ) from exc

    print('\n' + '=' * 58)
    print('  СМЕНА ПОРТА ЗАВЕРШЕНА')
    print('=' * 58)
    print(f'  Старый порт:      {old_port}/tcp — закрыт в UFW')
    print(f'  Новый порт:       {new_port}/tcp — открыт в UFW')
    print('  Xray:             конфигурация обновлена, служба перезапущена')
    print('  UUID, ключ, SNI:  без изменений')
    print(f'  Резервная копия:  {backup}')
    print('  Старый профиль:   порт больше не подходит — импортируй новую ссылку')
    print('=' * 58)
    try:
        show_link(args)
    except AraucariaError as exc:
        print(f'Новый порт работает, но ссылка не выведена: {exc}', file=sys.stderr)
        print('Используй: vless-link --ip ПУБЛИЧНЫЙ_IP', file=sys.stderr)
    print('Если у провайдера VPS есть внешний файрвол, открой новый TCP-порт и там.')


def show_commands(_args=None):
    print('\n' + '=' * 58)
    print('  ARAUCARIA | КОМАНДЫ УПРАВЛЕНИЯ')
    print('=' * 58)
    print('  vless-link           Показать актуальную VLESS-ссылку')
    print('  vless-rotate         Сменить UUID, ключи и Short ID')
    print('  vless-port           Выбрать новый порт (yes или число)')
    print('  vless-port --random  Выбрать случайный порт без вопроса')
    print('  vless-port 38421     Указать порт без вопроса')
    print('  vless-name           Переименовать профиль (интерактивно)')
    print('  vless-name "Мой VPN" Переименовать профиль сразу')
    print('  araucaria status     Проверить Xray, UFW и Fail2ban')
    print('  araucaria commands   Показать это меню команд')
    print('  araucaria --help     Полная справка')
    print('=' * 58 + '\n')


def create_parser():
    p = argparse.ArgumentParser(
        description='Araucaria VPS Manager — Xray VLESS + REALITY без панели.'
    )
    commands = p.add_subparsers(dest='action')
    init_p = commands.add_parser('init', help='Первая настройка Xray (вызывается установщиком)')
    init_p.add_argument('--port', type=int, required=True)
    init_p.add_argument('--target', default='www.google.com')
    init_p.add_argument('--name', default=DEFAULT_NAME)
    link_p = commands.add_parser('link', help='Показать актуальную VLESS-ссылку')
    link_p.add_argument('--ip', help='Внешний IPv4 адрес VPS, если автоопределение не работает')
    rotate_p = commands.add_parser('rotate', help='Сменить UUID, ключ REALITY и Short ID')
    rotate_p.add_argument('--ip', help='Внешний IPv4 адрес VPS')
    commands.add_parser('status', help='Статус Xray, UFW и Fail2ban')
    port_p = commands.add_parser('port', help='Сменить порт VLESS + REALITY с UFW и откатом')
    port_p.add_argument('port', nargs='?', type=int, help='Выбрать TCP-порт 1024–65535')
    port_p.add_argument('--random', action='store_true', help='Случайный свободный порт 20000–60000')
    port_p.add_argument('--ip', help='Внешний IPv4 для готовой ссылки')
    name_p = commands.add_parser('name', help='Переименовать VLESS-ссылку без перезапуска Xray')
    name_p.add_argument('name', nargs='?', help='Новое имя (до 64 символов, в кавычках если есть пробелы)')
    name_p.add_argument('--ip', help='Внешний IPv4 для готовой ссылки')
    commands.add_parser('commands', help='Показать команды управления')
    return p


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
        invoked = Path(sys.argv[0]).name
        if invoked == 'vless-link':
            argv = ['link', *argv]
        elif invoked == 'vless-rotate':
            argv = ['rotate', *argv]
        elif invoked == 'vless-port':
            argv = ['port', *argv]
        elif invoked == 'vless-name':
            argv = ['name', *argv]
    parser = create_parser()
    args = parser.parse_args(argv)
    if not args.action:
        parser.print_help()
        return 0
    try:
        {'init': init, 'rotate': rotate, 'link': show_link,
         'status': show_status, 'port': switch_vless_port, 'name': rename_vless,
         'commands': show_commands}[args.action](args)
    except AraucariaError as exc:
        print(f'Ошибка: {exc}', file=sys.stderr)
        return 1
    except (KeyError, TypeError, ValueError) as exc:
        print(f'Ошибка формата конфигурации: {exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
