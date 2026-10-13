#!/usr/bin/env python3
"""Araucaria VPS Manager: configuration, link export and safe credential rotation.

Only Python 3 standard-library modules are used.
"""

import argparse
import contextlib
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
    if not (1024 <= int(port) <= 65535):
        raise AraucariaError('Порт должен быть от 1024 до 65535.')
    return int(port)


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
    with exclusive_lock():
        previous = read_json(CONFIG_FILE)
        if previous.get('inbounds'):
            raise AraucariaError('В Xray уже есть входящие подключения. Ничего не перезаписываем.')
        if SETTINGS_FILE.exists():
            raise AraucariaError('Настройки Araucaria уже есть. Повторная установка отменена.')
        config = make_config(args.port, target)
        backup = apply_config(config)
        settings = {'name': args.name, 'created_utc': datetime.now(timezone.utc).isoformat()}
        save_json_private(SETTINGS_FILE, settings)
    print('VLESS + REALITY установлен и работает.')
    print(f'Порт: {args.port}; SNI: {target}; имя: {args.name}')
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
        f"{urlencode(params)}#{quote(name, safe='')}"
    )


def show_link(args):
    config = read_json(CONFIG_FILE)
    settings = read_json(SETTINGS_FILE)
    ip = public_ipv4(args.ip)
    inbound = find_inbound(config)
    client, reality = validate_inbound(inbound)
    link = make_link(config, ip, settings.get('name', DEFAULT_NAME))
    print('\n===== ARAUCARIA: VLESS + REALITY =====')
    print(f'IP:   {ip}')
    print(f"Порт: {inbound['port']}")
    print(f"SNI:  {reality['serverNames'][0]}")
    print(f"Имя:  {settings.get('name', DEFAULT_NAME)}")
    print('\nСсылка (не публикуй её):\n')
    print(link)
    print('\n=====================================\n')


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
    return p


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
        invoked = Path(sys.argv[0]).name
        if invoked == 'vless-link':
            argv = ['link', *argv]
        elif invoked == 'vless-rotate':
            argv = ['rotate', *argv]
    parser = create_parser()
    args = parser.parse_args(argv)
    if not args.action:
        parser.print_help()
        return 0
    try:
        {'init': init, 'rotate': rotate, 'link': show_link,
         'status': show_status}[args.action](args)
    except AraucariaError as exc:
        print(f'Ошибка: {exc}', file=sys.stderr)
        return 1
    except (KeyError, TypeError, ValueError) as exc:
        print(f'Ошибка формата конфигурации: {exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
