#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import json
import socket
import urllib.request
import urllib.parse
import base64
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.error import URLError, HTTPError

# ==================== НАСТРОЙКИ БРЕНДА ====================
# Укажите ссылку на ваш Telegram-канал здесь:
TG_CHANNEL_LINK = "https://t.me/your_telegram_channel"
# ==========================================================

# Основные настройки скрипта
LINKS_FILE = "links.txt"
OUTPUT_DIR = "configs"
BEST_LINKS_FILE = "best_files_links.txt"
MAX_CONFIGS_PER_FILE = 200
TCP_TIMEOUT = 2.5  # Максимальное время ожидания ответа от сервера (в секундах)
MAX_THREADS = 50   # Количество параллельных потоков для быстрой проверки

def decode_base64(data):
    """Безопасно декодирует строку из Base64."""
    cleaned_data = data.strip().replace("\n", "").replace("\r", "")
    missing_padding = len(cleaned_data) % 4
    if missing_padding:
        cleaned_data += '=' * (4 - missing_padding)
    
    try:
        decoded_bytes = base64.b64decode(cleaned_data)
        return decoded_bytes.decode('utf-8', errors='ignore')
    except Exception:
        return data

def encode_base64(text):
    """Кодирует строку в Base64 без лишних символов переноса строки."""
    text_bytes = text.encode('utf-8', errors='ignore')
    encoded_bytes = base64.b64encode(text_bytes)
    return encoded_bytes.decode('utf-8')

def parse_configs(content):
    """Извлекает прокси-ссылки популярных протоколов из загруженного текста."""
    decoded_content = decode_base64(content)
    protocols = ['vless', 'vmess', 'ss', 'ssr', 'trojan', 'shadowsocks', 'hysteria', 'tuic']
    pattern = r'(?:' + '|'.join(protocols) + r')://[^\s]+'
    
    configs = re.findall(pattern, decoded_content, re.IGNORECASE)
    if not configs:
        lines = [line.strip() for line in decoded_content.split('\n') if line.strip()]
        configs = [line for line in lines if any(line.startswith(p + "://") for p in protocols)]
        
    return list(set(configs)) # Удаляем дубликаты сразу

def sanitize_filename(name):
    """Создает безопасное имя файла из URL-адреса источника."""
    name = re.sub(r'https?://', '', name)
    name = re.sub(r'[^a-zA-Z0-9_\-]', '_', name)
    return name[:50]

def rename_config(config, new_name):
    """
    Переименовывает конфигурацию (меняет ее тег).
    Работает с vmess:// и другими протоколами (в конце после #).
    """
    try:
        if config.lower().startswith('vmess://'):
            schemeless = config[8:]
            decoded = decode_base64(schemeless)
            try:
                data = json.loads(decoded)
                data['ps'] = new_name
                encoded_json = json.dumps(data)
                return f"vmess://{encode_base64(encoded_json)}"
            except Exception:
                if '"ps"' in decoded:
                    new_decoded = re.sub(r'"ps"\s*:\s*"[^"]*"', f'"ps": "{new_name}"', decoded)
                    return f"vmess://{encode_base64(new_decoded)}"
                return config

        encoded_name = urllib.parse.quote(new_name)
        if '#' in config:
            base_url = config.split('#')[0]
            return f"{base_url}#{encoded_name}"
        else:
            return f"{config}#{encoded_name}"
    except Exception:
        return config

def extract_host_port(config):
    """Извлекает IP/домен и порт из конфигурации для TCP-проверки."""
    try:
        schemeless = re.sub(r'^[a-zA-Z0-9]+://', '', config)
        
        if config.lower().startswith('vmess://'):
            try:
                decoded = decode_base64(schemeless)
                if '"add"' in decoded and '"port"' in decoded:
                    add = re.search(r'"add"\s*:\s*"([^"]+)"', decoded)
                    port = re.search(r'"port"\s*:\s*"?(\d+)"?', decoded)
                    if add and port:
                        return add.group(1), int(port.group(1))
            except Exception:
                pass

        clean_uri = schemeless.split('?')[0].split('#')[0]
        if '@' in clean_uri:
            connection_part = clean_uri.split('@')[-1]
        else:
            connection_part = clean_uri

        if ']' in connection_part:
            match = re.search(r'\[(.*?)\]:(\d+)', connection_part)
            if match:
                return match.group(1), int(match.group(2))
        
        if ':' in connection_part:
            parts = connection_part.split(':')
            host = parts[0]
            port_match = re.match(r'^(\d+)', parts[1])
            if port_match:
                return host, int(port_match.group(1))
    except Exception:
        pass
    return None

def test_tcp_connection(config):
    """Пытается открыть TCP-соединение с хостом прокси."""
    target = extract_host_port(config)
    if not target:
        return None
        
    host, port = target
    start_time = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=TCP_TIMEOUT) as sock:
            latency = (time.perf_counter() - start_time) * 1000
            return config, latency
    except (socket.timeout, socket.error, ValueError):
        return None

def check_all_configs_parallel(all_configs):
    """Выполняет многопоточную проверку связи по TCP."""
    print(f"Начинаем проверку {len(all_configs)} уникальных конфигураций в {MAX_THREADS} потоков...")
    valid_configs = []
    
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {executor.submit(test_tcp_connection, cfg): cfg for cfg in all_configs if cfg}
        completed_count = 0
        for future in as_completed(futures):
            result = future.result()
            if result:
                valid_configs.append(result)
            completed_count += 1
            if completed_count % 50 == 0 or completed_count == len(all_configs):
                print(f"Проверено: {completed_count}/{len(all_configs)}...")
                
    valid_configs.sort(key=lambda x: x[1])
    return [item[0] for item in valid_configs]

def generate_file_content(configs, start_index=1):
    """Создает содержимое файла с метаданными бренда в начале."""
    header_lines = [
        "# Название: 🍟ImprovedVPN",
        "# Безлимит пользования без ограничений",
        f"# Описание : Мой ТГК - {TG_CHANNEL_LINK}",
        f"# ссылка на канал : {TG_CHANNEL_LINK}",
        ""
    ]
    
    processed_configs = []
    for idx, config in enumerate(configs, start=1):
        display_number = start_index + idx - 1
        new_name = f"🍟Improved-potato [{display_number}]"
        renamed = rename_config(config, new_name)
        processed_configs.append(renamed)
        
    full_content = "\n".join(header_lines + processed_configs) + "\n"
    return full_content

def fetch_and_save():
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)
        
    if not os.path.exists(LINKS_FILE):
        print(f"Файл {LINKS_FILE} не найден.")
        return
        
    with open(LINKS_FILE, 'r', encoding='utf-8') as f:
        links = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
        
    if not links:
        print("Список ссылок пуст.")
        return

    all_gathered_configs = []

    # 1. Скачивание конфигов
    for index, link in enumerate(links, start=1):
        print(f"[{index}/{len(links)}] Скачивание: {link}")
        base_name = sanitize_filename(link)
        
        try:
            req = urllib.request.Request(
                link, 
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            )
            with urllib.request.urlopen(req, timeout=15) as response:
                content = response.read().decode('utf-8', errors='ignore')
        except Exception as e:
            print(f"Ошибка при загрузке {link}: {e}")
            continue

        configs = parse_configs(content)
        total_configs = len(configs)
        print(f"Найдено: {total_configs}")
        
        if total_configs == 0:
            continue
            
        all_gathered_configs.extend(configs)

        part = 1
        for i in range(0, total_configs, MAX_CONFIGS_PER_FILE):
            chunk = configs[i:i + MAX_CONFIGS_PER_FILE]
            filename = f"{base_name}.txt" if total_configs <= MAX_CONFIGS_PER_FILE else f"{base_name}_part{part}.txt"
            filepath = os.path.join(OUTPUT_DIR, filename)
            
            file_content = generate_file_content(chunk, start_index=1)
            with open(filepath, 'w', encoding='utf-8') as out_file:
                out_file.write(file_content)
            part += 1

    unique_gathered_configs = list(set(all_gathered_configs))
    print(f"\nВсего уникальных для проверки: {len(unique_gathered_configs)}")

    if not unique_gathered_configs:
        return

    # 2. Проверка по TCP
    best_sorted_configs = check_all_configs_parallel(unique_gathered_configs)

    if not best_sorted_configs:
        print("Нет рабочих прокси.")
        return

    # 3. Сохранение лучших файлов
    best_file_paths = []
    
    best_1_chunk = best_sorted_configs[0:MAX_CONFIGS_PER_FILE]
    if best_1_chunk:
        path_1 = os.path.join(OUTPUT_DIR, "best_1.txt")
        file_content_1 = generate_file_content(best_1_chunk, start_index=1)
        with open(path_1, 'w', encoding='utf-8') as f:
            f.write(file_content_1)
        best_file_paths.append(path_1)

    best_2_chunk = best_sorted_configs[MAX_CONFIGS_PER_FILE:MAX_CONFIGS_PER_FILE * 2]
    if best_2_chunk:
        path_2 = os.path.join(OUTPUT_DIR, "best_2.txt")
        file_content_2 = generate_file_content(best_2_chunk, start_index=201)
        with open(path_2, 'w', encoding='utf-8') as f:
            f.write(file_content_2)
        best_file_paths.append(path_2)

    # 4. Ссылки на файлы
    github_repository = os.environ.get("GITHUB_REPOSITORY", "USER/REPO")
    raw_url_base = f"https://raw.githubusercontent.com/{github_repository}/main"
    
    try:
        with open(BEST_LINKS_FILE, 'w', encoding='utf-8') as link_file:
            link_file.write("# Прямые ссылки на лучшие конфигурации\n\n")
            link_file.write("## RAW GitHub ссылки:\n")
            for path in best_file_paths:
                link_file.write(f"{raw_url_base}/{path}\n")
    except Exception as e:
        print(f"Ошибка записи ссылок: {e}")

if __name__ == "__main__":
    fetch_and_save()
    print("\nУспешно!")
