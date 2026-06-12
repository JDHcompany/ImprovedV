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
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.error import URLError, HTTPError

# ==================== НАСТРОЙКИ БРЕНДА ====================
# Ссылка на вашего Telegram-бота (используется для отображения на сайте)
TG_CHANNEL_LINK = "https://t.me/freevpnconf_bot"
# ==========================================================

# Основные настройки скрипта
LINKS_FILE = "links.txt"
OUTPUT_DIR = "configs"
BEST_LINKS_FILE = "best_files_links.txt"
MANIFEST_FILE = os.path.join(OUTPUT_DIR, "manifest.json")
MAX_CONFIGS_PER_FILE = 200
TCP_TIMEOUT = 1.5  # Таймаут для проверки связи
MAX_THREADS = 150   # 150 параллельных потоков
LIMIT_TEST_CONFIGS = 1500 # Лимит проверяемых прокси для экономии времени

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
    """Кодирует строку в Base64."""
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
        
    return list(set(configs))

def sanitize_filename(name):
    """Создает безопасное имя файла из URL-адреса источника."""
    name = re.sub(r'https?://', '', name)
    name = re.sub(r'[^a-zA-Z0-9_\-]', '_', name)
    return name[:50]

def rename_config(config, new_name):
    """Переименовывает имя соединения в конфигурации."""
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
    """Извлекает IP/домен и порт из конфигурации."""
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
    """Выполняет ультрабыструю многопоточную проверку связи по TCP."""
    total_count = len(all_configs)
    
    if total_count > LIMIT_TEST_CONFIGS:
        print(f"База слишком большая ({total_count} шт). Выбираем случайные {LIMIT_TEST_CONFIGS} для быстрого TCP-теста...")
        configs_to_test = random.sample(all_configs, LIMIT_TEST_CONFIGS)
    else:
        configs_to_test = all_configs

    print(f"Начинаем проверку {len(configs_to_test)} конфигураций в {MAX_THREADS} потоков...")
    valid_configs = []
    
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {executor.submit(test_tcp_connection, cfg): cfg for cfg in configs_to_test if cfg}
        completed_count = 0
        for future in as_completed(futures):
            result = future.result()
            if result:
                valid_configs.append(result)
            completed_count += 1
            if completed_count % 150 == 0 or completed_count == len(configs_to_test):
                print(f"Проверено: {completed_count}/{len(configs_to_test)}...")
                
    valid_configs.sort(key=lambda x: x[1])
    return [item[0] for item in valid_configs]

def generate_hybrid_html(configs, filename_display, start_index=1):
    """
    Генерирует гибридный HTML-файл.
    При запуске в браузере он рендерит красивую страницу подписки.
    При чтении клиентом Happ — отдает только чистые конфиги из скрытого блока.
    """
    metadata_lines = [
        "# profile-title: 💩improved-potatoVPN🍀|TG @freevpncons_bot",
        "# profile-update-interval: 1",
        "# subscription-userinfo: upload=9999999999999999999; download=0; total=9999999999999999999; expire=4102444800",
        "# support-url: https://t.me/freevpnconf_bot",
        "# announce: Больше конфигов в моем ТГ боте- https://t.me/freevpnconf_bot",
        ""
    ]
    
    processed_configs = []
    for idx, config in enumerate(configs, start=1):
        display_number = start_index + idx - 1
        new_name = f"🍟Improved-potato [{display_number}]"
        renamed = rename_config(config, new_name)
        processed_configs.append(renamed)
        
    plain_configs = "\n".join(metadata_lines + processed_configs)
    
    # HTML-шаблон, который рендерит полноценный сайт прямо на этом же URL
    html_content = f"""<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🍟 ImprovedVPN — Подписка</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://unpkg.com/lucide@latest"></script>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&display=swap');
        body {{
            font-family: 'Plus Jakarta Sans', sans-serif;
            background-color: #0b0f19;
        }}
        .glow-effect {{
            box-shadow: 0 0 25px -5px rgba(245, 158, 11, 0.3);
        }}
        .card-blur {{
            background: rgba(17, 24, 39, 0.7);
            backdrop-filter: blur(12px);
            border: 1px solid rgba(255, 255, 255, 0.05);
        }}
    </style>
</head>
<body class="text-gray-100 min-h-screen flex flex-col justify-between selection:bg-amber-500 selection:text-black">
    <div class="absolute top-0 left-1/4 w-96 h-96 bg-amber-600/10 rounded-full blur-[100px] pointer-events-none"></div>
    <div class="absolute bottom-10 right-1/4 w-96 h-96 bg-orange-600/10 rounded-full blur-[100px] pointer-events-none"></div>

    <div class="max-w-xl w-full mx-auto px-4 py-16 z-10 my-auto">
        <div class="card-blur p-8 rounded-3xl glow-effect text-center border border-amber-500/20">
            <div class="inline-flex items-center justify-center p-3 bg-amber-500/10 rounded-2xl mb-6">
                <span class="text-4xl">🍟</span>
            </div>
            <h1 class="text-3xl font-extrabold bg-gradient-to-r from-amber-400 to-orange-400 bg-clip-text text-transparent">
                ImprovedVPN
            </h1>
            <p class="text-sm text-gray-400 mt-2">Ваша персональная подписка готова к работе!</p>
            
            <div class="my-6 p-4 bg-gray-950/50 rounded-2xl border border-gray-800 text-left">
                <div class="text-xs text-gray-500">Имя подписки:</div>
                <div class="text-base font-bold text-white mt-1">🍟 Improved-potato</div>
                <div class="text-xs text-gray-500 mt-3">Количество конфигураций в файле:</div>
                <div class="text-base font-bold text-amber-400 mt-1">{len(processed_configs)} шт</div>
            </div>

            <button onclick="copyCurrentUrl()" class="w-full flex items-center justify-center gap-2 bg-gradient-to-r from-amber-500 to-orange-600 text-black font-bold py-3.5 px-6 rounded-xl transition duration-200 transform hover:scale-[1.02]">
                <i data-lucide="copy" class="w-5 h-5"></i>
                Скопировать ссылку на подписку
            </button>

            <a href="{TG_CHANNEL_LINK}" target="_blank" class="mt-4 w-full flex items-center justify-center gap-2 bg-gray-900 hover:bg-gray-800 text-gray-300 font-bold py-3.5 px-6 rounded-xl transition duration-200 border border-gray-800">
                <i data-lucide="bot" class="w-5 h-5"></i>
                Наш Telegram-бот
            </a>
        </div>
    </div>

    <!-- Всплывающий тост -->
    <div id="toast" class="fixed bottom-5 right-5 transform translate-y-20 opacity-0 transition-all duration-300 ease-out z-50 flex items-center gap-3 bg-gray-950 text-white border border-green-500/30 px-5 py-4 rounded-2xl shadow-2xl">
        <div class="p-1 bg-green-500/20 text-green-400 rounded-lg">
            <i data-lucide="check" class="w-5 h-5"></i>
        </div>
        <div>
            <div class="font-bold text-sm">Ссылка скопирована!</div>
            <div class="text-xs text-gray-400 mt-0.5">Добавьте ее в Nekobox или Happ</div>
        </div>
    </div>

    <script>
        lucide.createIcons();
        function copyCurrentUrl() {{
            const el = document.createElement('textarea');
            el.value = window.location.href;
            document.body.appendChild(el);
            el.select();
            document.execCommand('copy');
            document.body.removeChild(el);

            const toast = document.getElementById('toast');
            toast.classList.remove('translate-y-20', 'opacity-0');
            toast.classList.add('translate-y-0', 'opacity-100');
            setTimeout(() => {{
                toast.classList.remove('translate-y-0', 'opacity-100');
                toast.classList.add('translate-y-20', 'opacity-0');
            }}, 3000);
        }}
    </script>

    <!-- СКРЫТЫЙ БЛОК ДЛЯ VPN КЛИЕНТОВ (ОНИ СЧИТАЮТ ТОЛЬКО ЭТО) -->
    <!--
    {plain_configs}
    -->
</body>
</html>"""
    return html_content

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
    manifest_sources = []

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
        source_files = []
        for i in range(0, total_configs, MAX_CONFIGS_PER_FILE):
            chunk = configs[i:i + MAX_CONFIGS_PER_FILE]
            filename = f"{base_name}.html" if total_configs <= MAX_CONFIGS_PER_FILE else f"{base_name}_part{part}.html"
            filepath = os.path.join(OUTPUT_DIR, filename)
            
            file_content = generate_hybrid_html(chunk, f"improved-potato-part{part}", start_index=1)
            with open(filepath, 'w', encoding='utf-8') as out_file:
                out_file.write(file_content)
                
            source_files.append({
                "filename": filename,
                "filepath": f"configs/{filename}",
                "count": len(chunk),
                "part": part
            })
            part += 1
            
        manifest_sources.append({
            "source_url": link,
            "friendly_name": base_name,
            "total_count": total_configs,
            "files": source_files
        })

    unique_gathered_configs = list(set(all_gathered_configs))
    print(f"\nВсего уникальных для проверки: {len(unique_gathered_configs)}")

    best_file_paths = []
    best_manifest_files = []

    if unique_gathered_configs:
        best_sorted_configs = check_all_configs_parallel(unique_gathered_configs)

        if best_sorted_configs:
            # Файл 1: Топ 1-200 лучших
            best_1_chunk = best_sorted_configs[0:MAX_CONFIGS_PER_FILE]
            if best_1_chunk:
                path_1 = os.path.join(OUTPUT_DIR, "best_1.html")
                file_content_1 = generate_hybrid_html(best_1_chunk, "best_1", start_index=1)
                with open(path_1, 'w', encoding='utf-8') as f:
                    f.write(file_content_1)
                best_file_paths.append(path_1)
                best_manifest_files.append({
                    "name": "🔥 Лучшие прокси — Часть 1",
                    "filepath": "configs/best_1.html",
                    "count": len(best_1_chunk),
                    "description": "Самые быстрые проверенные серверы (топ 1-200 по пингу)."
                })

            # Файл 2: Топ 201-400 лучших
            best_2_chunk = best_sorted_configs[MAX_CONFIGS_PER_FILE:MAX_CONFIGS_PER_FILE * 2]
            if best_2_chunk:
                path_2 = os.path.join(OUTPUT_DIR, "best_2.html")
                file_content_2 = generate_hybrid_html(best_2_chunk, "best_2", start_index=201)
                with open(path_2, 'w', encoding='utf-8') as f:
                    f.write(file_content_2)
                best_file_paths.append(path_2)
                best_manifest_files.append({
                    "name": "⚡ Резервные прокси — Часть 2",
                    "filepath": "configs/best_2.html",
                    "count": len(best_2_chunk),
                    "description": "Дополнительный пул качественных серверов (топ 201-400)."
                })

    # Записываем манифест JSON для веб-сайта
    manifest_data = {
        "last_updated": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "telegram": TG_CHANNEL_LINK,
        "best_files": best_manifest_files,
        "sources": manifest_sources
    }
    
    with open(MANIFEST_FILE, 'w', encoding='utf-8') as mf:
        json.dump(manifest_data, mf, ensure_ascii=False, indent=2)
    print(f"Манифест сохранен in {MANIFEST_FILE}")

    # Запись ссылок
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
    print("\nУспешно завершено!")
