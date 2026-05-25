import base64
import json
import re
import socket
import urllib.request
import html
import time
import os
import ssl
import random
from collections import defaultdict
from urllib.parse import urlparse, unquote, quote
from concurrent.futures import ThreadPoolExecutor, as_completed

# =====================================================================
# СЛОВАРЬ СТРАН (Определен на самом верху для предотвращения NameError)
# =====================================================================
COUNTRY_INFO = {
    "RU": {"flag": "🇷🇺", "ru_name": "Россия"},
    "US": {"flag": "🇺🇸", "ru_name": "США"},
    "DE": {"flag": "🇩🇪", "ru_name": "Германия"},
    "NL": {"flag": "🇳🇱", "ru_name": "Нидерланды"},
    "FI": {"flag": "🇫🇮", "ru_name": "Финляндия"},
    "GB": {"flag": "🇬🇧", "ru_name": "Великобритания"},
    "FR": {"flag": "🇫🇷", "ru_name": "Франция"},
    "PL": {"flag": "🇵🇱", "ru_name": "Польша"},
    "KZ": {"flag": "🇰🇿", "ru_name": "Казахстан"},
    "TR": {"flag": "🇹🇷", "ru_name": "Турция"},
    "SG": {"flag": "🇸🇬", "ru_name": "Сингапур"},
    "JP": {"flag": "🇯🇵", "ru_name": "Япония"},
    "EE": {"flag": "🇪🇪", "ru_name": "Эстония"},
    "SE": {"flag": "🇸🇪", "ru_name": "Швеция"},
    "CA": {"flag": "🇨🇦", "ru_name": "Канада"},
    "BY": {"flag": "🇧🇾", "ru_name": "Беларусь"},
    "HK": {"flag": "🇭🇰", "ru_name": "Гонконг"},
    "CH": {"flag": "🇨🇭", "ru_name": "Швейцария"},
    "AT": {"flag": "🇦🇹", "ru_name": "Австрия"},
    "ES": {"flag": "🇪🇸", "ru_name": "Испания"},
    "IT": {"flag": "🇮🇹", "ru_name": "Италия"},
    "UA": {"flag": "🇺🇦", "ru_name": "Украина"},
    "RO": {"flag": "🇷🇴", "ru_name": "Румыния"},
    "BG": {"flag": "🇧🇬", "ru_name": "Болгария"},
    "KR": {"flag": "🇰🇷", "ru_name": "Южная Корея"},
}

# Название локального файла для копирования конфигов из чатов/групп
LOCAL_FILE = "local_configs.txt"

# Специфический источник (Белые списки РФ / обход блокировок)
SPECIAL_RU_SOURCE = "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/Vless-Reality-White-Lists-Rus-Mobile.txt"

# Общие Telegram-каналы для парсинга
TELEGRAM_CHANNELS = [
    "LetoVPN_free"
]

# Общие источники (проверенные)
RAW_URLS = [
    "https://raw.githubusercontent.com/adop1344-bot/LetoVPN_free/refs/heads/main/ru.txt",
    "https://raw.githubusercontent.com/F0rc3Run/F0rc3Run/refs/heads/main/Best-Results/proxies.txt",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/refs/heads/main/Sub1.txt"
]

CONFIG_REGEX = re.compile(r'(?:vless|vmess|ss|trojan|hysteria2|tuic)://[^\s"<]+')

GEOIP_CACHE = {}
geoip_calls_count = 0
MAX_GEOIP_CALLS = 40

def decode_if_base64(text):
    clean_text = text.strip()
    if re.match(r'^[A-Za-z0-9+/=\s\n\r]+$', clean_text) and not clean_text.startswith("vless://") and not clean_text.startswith("vmess://") and len(clean_text) > 40:
        try:
            clean_text += "=" * ((4 - len(clean_text) % 4) % 4)
            decoded = base64.b64decode(clean_text).decode('utf-8', errors='ignore')
            return decoded
        except Exception:
            pass
    return text

def fetch_local_file():
    if not os.path.exists(LOCAL_FILE):
        try:
            with open(LOCAL_FILE, "w", encoding="utf-8") as f:
                f.write("# Вставьте сюда скопированный текст из Telegram-групп (например, @russiawirevpn)\n")
                f.write("# Скрипт автоматически извлечет из него ссылки при запуске!\n")
        except Exception:
            pass
        return []
        
    try:
        with open(LOCAL_FILE, "r", encoding="utf-8") as f:
            content = f.read()
            configs = CONFIG_REGEX.findall(content)
            if configs:
                print(f"[+] Из файла {LOCAL_FILE} успешно извлечено {len(configs)} конфигураций.")
            return configs
    except Exception as e:
        print(f"[-] Ошибка при чтении файла {LOCAL_FILE}: {e}")
        return []

def fetch_raw_url(url):
    headers = {"User-Agent": "Mozilla/5.0"}
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            content = response.read().decode('utf-8', errors='ignore')
            content = decode_if_base64(content)
            configs = CONFIG_REGEX.findall(content)
            print(f"[+] Из источника {url[:60]}... извлечено {len(configs)} конфигураций.")
            return configs
    except Exception as e:
        print(f"[-] Ошибка загрузки {url}: {e}")
        return []

def fetch_telegram_channel(channel_username):
    url = f"https://t.me/s/{channel_username}"
    headers = {"User-Agent": "Mozilla/5.0"}
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            html_content = response.read().decode('utf-8', errors='ignore')
            html_content = html.unescape(html_content)
            configs = CONFIG_REGEX.findall(html_content)
            print(f"[+] Из Telegram @{channel_username} извлечено {len(configs)} конфигураций.")
            return configs
    except Exception as e:
        print(f"[-] Ошибка парсинга Telegram @{channel_username}: {e}")
        return []

def decode_base64_vmess(vmess_str):
    try:
        b64_data = vmess_str[8:]
        b64_data += "=" * ((4 - len(b64_data) % 4) % 4)
        decoded = base64.b64decode(b64_data).decode('utf-8', errors='ignore')
        return json.loads(decoded)
    except Exception:
        return None

def parse_config(config_str):
    try:
        if "127.0.0.1" in config_str or "localhost" in config_str:
            return None
            
        if config_str.startswith("vmess://"):
            data = decode_base64_vmess(config_str)
            if data:
                is_tls = data.get("tls") == "tls"
                is_ws = data.get("net") == "ws"
                path = data.get("path", "/")
                host_header = data.get("host")
                return {
                    "protocol": "vmess",
                    "host": data.get("add"),
                    "port": int(data.get("port", 443)),
                    "name": data.get("ps", ""),
                    "is_tls": is_tls,
                    "is_ws": is_ws,
                    "path": path,
                    "host_header": host_header,
                    "sni": data.get("sni"),
                    "raw": config_str
                }
        else:
            parsed = urlparse(config_str)
            protocol = parsed.scheme
            netloc = parsed.netloc
            if "@" in netloc:
                _, host_port = netloc.rsplit("@", 1)
            else:
                host_port = netloc
            
            if ":" in host_port:
                host, port_str = host_port.rsplit(":", 1)
                port = int(port_str)
            else:
                host = host_port
                port = 443
                
            name = unquote(parsed.fragment) if parsed.fragment else ""
            
            is_tls = False
            sni = None
            is_ws = False
            path = "/"
            host_header = None
            
            if parsed.query:
                try:
                    params = dict(x.split("=", 1) for x in parsed.query.split("&") if "=" in x)
                    security = params.get("security", "").lower()
                    if security in ["tls", "reality"]:
                        is_tls = True
                    sni = params.get("sni")
                    
                    transport_type = params.get("type", "").lower()
                    if transport_type == "ws":
                        is_ws = True
                    path = params.get("path", "/")
                    host_header = params.get("host")
                except Exception:
                    pass
            
            if protocol in ["trojan", "hysteria2", "tuic"]:
                is_tls = True
                
            return {
                "protocol": protocol,
                "host": host,
                "port": port,
                "name": name,
                "is_tls": is_tls,
                "sni": sni,
                "is_ws": is_ws,
                "path": path,
                "host_header": host_header,
                "raw": config_str
            }
    except Exception:
        pass
    return None

def detect_country_from_name(name):
    if not name:
        return None
    name_upper = name.upper()
    
    country_flags = {
        "🇷🇺": "RU", "🇺🇸": "US", "🇩🇪": "DE", "🇳🇱": "NL", "🇫🇮": "FI", 
        "🇬🇧": "GB", "🇫🇷": "FR", "🇵🇱": "PL", "🇰🇿": "KZ", "🇧🇾": "BY", 
        "🇹🇷": "TR", "🇸🇬": "SG", "🇯🇵": "JP", "🇸🇪": "SE", "🇨🇦": "CA",
        "🇪🇪": "EE", "🇰🇷": "KR"
    }
    for flag, code in country_flags.items():
        if flag in name:
            return code
            
    patterns = {
        "RU": r"\b(RU|RUS|RUSSIA|РОССИЯ|РФ)\b",
        "US": r"\b(US|USA|UNITED STATES)\b",
        "DE": r"\b(DE|GER|GERMANY|ГЕРМАНИЯ)\b",
        "NL": r"\b(NL|NETHERLANDS|НИДЕРЛАНДЫ|AMS)\b",
        "FI": r"\b(FI|FIN|FINLAND|ФИНЛЯНДИЯ)\b",
        "GB": r"\b(GB|UK|UNITED KINGDOM|ВЕЛИКОБРИТАНИЯ)\b",
        "FR": r"\b(FR|FRA|FRANCE|ФРАНЦИЯ)\b",
        "PL": r"\b(PL|POL|POLAND|ПОЛЬША)\b",
        "KZ": r"\b(KZ|KAZ|KAZAKHSTAN|КАЗАХСТАН)\b",
        "TR": r"\b(TR|TUR|TURKEY|ТУРЦИЯ)\b",
        "SG": r"\b(SG|SGP|SINGAPORE|СИНГАПУР)\b",
        "JP": r"\b(JP|JPN|JAPAN|ЯПОНИЯ)\b",
        "EE": r"\b(EE|EST|ESTONIA|ЭСТОНИЯ)\b",
        "SE": r"\b(SE|SWE|SWEDEN|ШВЕЦИЯ)\b",
        "KR": r"\b(KR|KOR|KOREA|КОРЕЯ|СЕУЛ)\b",
    }
    
    for country, pattern in patterns.items():
        if re.search(pattern, name_upper):
            return country
    return None

def pre_filter_raw_configs(raw_strings, max_per_country_pre=10):
    by_est_country = defaultdict(list)
    unknown_list = []
    
    for raw in raw_strings:
        parsed = parse_config(raw)
        if not parsed:
            continue
        est_country = detect_country_from_name(parsed["name"])
        if est_country:
            by_est_country[est_country].append(raw)
        else:
            unknown_list.append(raw)
            
    pre_selected = []
    for country, items in by_est_country.items():
        pre_selected.extend(items[:max_per_country_pre])
        
    pre_selected.extend(unknown_list[:40])
    return list(set(pre_selected))

def test_websocket_node(ip, port, is_tls, host, path, host_header=None, timeout=2.5):
    if not host_header:
        host_header = host
    if not path:
        path = "/"
    if not path.startswith("/"):
        path = "/" + path
        
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        f"Sec-WebSocket-Version: 13\r\n\r\n"
    )
    
    try:
        if is_tls:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host_header) as ssl_sock:
                    ssl_sock.sendall(req.encode('utf-8'))
                    res = ssl_sock.recv(1024).decode('utf-8', errors='ignore')
        else:
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                sock.sendall(req.encode('utf-8'))
                res = sock.recv(1024).decode('utf-8', errors='ignore')
                
        if "HTTP/1.1 101" in res:
            return True
        if "HTTP/1.1 400" in res and "cloudflare" not in res.lower():
            return True
            
        return False
    except Exception:
        return False

def test_node_connection(host, port, protocol, is_tls=False, sni=None, is_ws=False, path=None, host_header=None, timeout=2.5):
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        return None
        
    if is_ws:
        success = test_websocket_node(ip, port, is_tls, host, path, host_header, timeout)
        return ip if success else None
        
    if is_tls:
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=sni if sni else host) as ssl_sock:
                    return ip
        except Exception:
            return None
    else:
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                return ip
        except Exception:
            return None

def check_tls_or_tcp_worker(raw_conf):
    parsed = parse_config(raw_conf)
    if not parsed:
        return None
    ip = test_node_connection(
        host=parsed["host"],
        port=parsed["port"],
        protocol=parsed["protocol"],
        is_tls=parsed.get("is_tls", False),
        sni=parsed.get("sni"),
        is_ws=parsed.get("is_ws", False),
        path=parsed.get("path", "/"),
        host_header=parsed.get("host_header"),
        timeout=2.5
    )
    if ip:
        parsed["ip"] = ip
        return parsed
    return None

def get_country_code(ip, name):
    global geoip_calls_count
    
    detected = detect_country_from_name(name)
    if detected:
        return detected
        
    if ip in GEOIP_CACHE:
        return GEOIP_CACHE[ip]
        
    if geoip_calls_count >= MAX_GEOIP_CALLS:
        return "Unknown"
        
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,countryCode"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=3) as response:
            data = json.loads(response.read().decode('utf-8'))
            if data.get("status") == "success":
                country = data.get("countryCode", "Unknown")
                GEOIP_CACHE[ip] = country
                geoip_calls_count += 1
                time.sleep(1.2)
                return country
    except Exception:
        pass
        
    return "Unknown"

def get_rename_tag(country_code, index):
    global COUNTRY_INFO
    
    local_info = {
        "RU": "Россия", "US": "США", "DE": "Германия", "NL": "Нидерланды",
        "FI": "Финляндия", "GB": "Великобритания", "FR": "Франция", "PL": "Польша",
        "KZ": "Казахстан", "TR": "Турция", "SG": "Сингапур", "JP": "Япония",
        "EE": "Эстония", "SE": "Швеция", "CA": "Канада", "BY": "Беларусь",
        "HK": "Гонконг", "CH": "Швейцария", "AT": "Австрия", "ES": "Испания",
        "IT": "Италия", "UA": "Украина", "RO": "Румыния", "BG": "Болгария",
        "KR": "Южная Корея"
    }
    
    try:
        info = COUNTRY_INFO.get(country_code)
    except NameError:
        info = None
        
    if info:
        return f"{info['flag']} {info['ru_name']} #{index}"
    else:
        ru_name = local_info.get(country_code, country_code)
        if len(country_code) == 2 and country_code != "UN" and country_code != "Unknown":
            try:
                flag = "".join(chr(127397 + ord(c)) for c in country_code)
                return f"{flag} {ru_name} #{index}"
            except Exception:
                pass
        return f"🌐 Unknown #{index}"

def rename_non_vmess_config(raw_url, new_name):
    if "#" in raw_url:
        base_url = raw_url.rsplit("#", 1)[0]
    else:
        base_url = raw_url
    return f"{base_url}#{quote(new_name)}"

def rename_vmess_config(raw_url, new_name):
    data = decode_base64_vmess(raw_url)
    if not data:
        return raw_url
    data["ps"] = new_name
    json_str = json.dumps(data)
    encoded = base64.b64encode(json_str.encode("utf-8")).decode("utf-8")
    return f"vmess://{encoded}"

def verify_configs_optimized(raw_configs, max_workers=25):
    if not raw_configs:
        return []
    alive_configs = []
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(check_tls_or_tcp_worker, r): r for r in raw_configs}
        for future in as_completed(futures):
            try:
                res = future.result()
                if res:
                    alive_configs.append(res)
            except Exception:
                pass
                
    verified = []
    for conf in alive_configs:
        country = get_country_code(conf["ip"], conf["name"])
        conf["country"] = country
        verified.append(conf)
        
    return verified

def process_special_ru_source():
    print(f"\n[*] Специфический сбор из источника: {SPECIAL_RU_SOURCE}")
    raw_configs = fetch_raw_url(SPECIAL_RU_SOURCE)
    unique_raw = list(set(raw_configs))
    
    optimized_raw = pre_filter_raw_configs(unique_raw, max_per_country_pre=10)
    
    print(f"[*] Проверка {len(optimized_raw)} серверов из спец. источника в многопоточном режиме...")
    alive_configs = []
    with ThreadPoolExecutor(max_workers=25) as executor:
        futures = {executor.submit(check_tls_or_tcp_worker, r): r for r in optimized_raw}
        for future in as_completed(futures):
            try:
                res = future.result()
                if res:
                    alive_configs.append(res)
            except Exception:
                pass
                
    ru_working_configs = []
    fallback_working_configs = []
    
    print("[*] Определение геолокации для спец. источника...")
    for conf in alive_configs:
        country = get_country_code(conf["ip"], conf["name"])
        conf["country"] = country
        
        if country == "RU":
            ru_working_configs.append(conf)
            print(f"    [+] Найдено RU из спец. источника: {conf['protocol']}://{conf['host']}:{conf['port']}")
            if len(ru_working_configs) >= 5:
                break
        else:
            fallback_working_configs.append(conf)
            
    if len(ru_working_configs) < 5:
        needed = 5 - len(ru_working_configs)
        print(f"[!] В РФ физически находится только {len(ru_working_configs)} рабочих узлов.")
        print(f"[*] Добираем еще {needed} рабочих узлов из этого же оптимизированного под РФ файла...")
        for conf in fallback_working_configs[:needed]:
            ru_working_configs.append(conf)
            print(f"    [+] Добавлен резервный рабочий узел ({conf['country']}): {conf['protocol']}://{conf['host']}:{conf['port']}")
            
    return ru_working_configs[:5]

def run_aggregation():
    global geoip_calls_count
    geoip_calls_count = 0
    
    selected_by_country = defaultdict(list)
    selected_raws = set()
    
    # 1. ЗАГРУЖАЕМ И ПРОВЕРЯЕМ СТАРЫЕ КОНФИГУРАЦИИ
    old_configs = []
    if os.path.exists("subscription.txt"):
        try:
            with open("subscription.txt", "r", encoding="utf-8") as f:
                content = f.read()
                old_configs = CONFIG_REGEX.findall(content)
        except Exception:
            pass
            
    if old_configs:
        unique_old = list(set(old_configs))
        print(f"[*] Найдено {len(unique_old)} сохраненных конфигураций из предыдущей подписки.")
        print("[*] Проверка старых конфигураций в первую очередь...")
        alive_old = verify_configs_optimized(unique_old)
        
        for conf in alive_old:
            country = conf["country"]
            if len(selected_by_country[country]) < 5 and len(selected_raws) < 50:
                selected_by_country[country].append(conf)
                selected_raws.add(conf["raw"])
                print(f"    [+] Старый рабочий сервер сохранен: {conf['protocol']}://{conf['host']}:{conf['port']} ({country})")
                
    total_selected = len(selected_raws)
    print(f"[*] После проверки старой подписки сохранено рабочих узлов: {total_selected}/50.")
    
    # 2. ЕСЛИ УЗЛОВ МЕНЬШЕ 50 — ДОБИРАЕМ ИЗ НОВЫХ ИСТОЧНИКОВ
    if total_selected < 50:
        print("[*] Начинаем сбор новых конфигураций для добора...")
        new_raw_configs = []
        
        new_raw_configs.extend(fetch_local_file())
        special_ru_raws = fetch_raw_url(SPECIAL_RU_SOURCE)
        
        for channel in TELEGRAM_CHANNELS:
            new_raw_configs.extend(fetch_telegram_channel(channel))
        for url in RAW_URLS:
            new_raw_configs.extend(fetch_raw_url(url))
            
        all_new_raws = list(set(new_raw_configs + special_ru_raws) - selected_raws)
        
        raw_by_est_country = defaultdict(list)
        raw_unknown = []
        for r in all_new_raws:
            parsed = parse_config(r)
            if not parsed:
                continue
            est = detect_country_from_name(parsed["name"])
            if est:
                raw_by_est_country[est].append(r)
            else:
                raw_unknown.append(r)
                
        for country in raw_by_est_country:
            random.shuffle(raw_by_est_country[country])
        random.shuffle(raw_unknown)
        
        test_queue = []
        index = 0
        has_more = True
        while has_more:
            has_more = False
            for country in list(raw_by_est_country.keys()):
                if index < len(raw_by_est_country[country]):
                    test_queue.append(raw_by_est_country[country][index])
                    has_more = True
            index += 1
        test_queue.extend(raw_unknown)
        
        batch_size = 15
        print(f"[*] Для тестирования доступно {len(test_queue)} новых кандидатов.")
        print(f"[*] Начинаем порционный опрос пачками по {batch_size} до заполнения лимита...")
        
        for i in range(0, len(test_queue), batch_size):
            if len(selected_raws) >= 50:
                break
                
            batch = test_queue[i:i+batch_size]
            print(f"[*] Проверка пачки из {len(batch)} новых кандидатов (WebSocket Handshake / TLS)...")
            verified_batch = verify_configs_optimized(batch)
            
            for conf in verified_batch:
                country = conf["country"]
                if len(selected_by_country[country]) < 5 and len(selected_raws) < 50:
                    selected_by_country[country].append(conf)
                    selected_raws.add(conf["raw"])
                    print(f"    [+] Добавлен новый сервер: {conf['protocol']}://{conf['host']}:{conf['port']} ({country})")
                    
                if len(selected_raws) >= 50:
                    break
                    
    # 3. СБОРКА И ПЕРЕИМЕНОВАНИЕ ФИНАЛЬНОГО СПИСКА
    final_selection = []
    for country in selected_by_country:
        final_selection.extend(selected_by_country[country])
        
    renamed_lines = []
    country_counters = defaultdict(int)
    
    for conf in final_selection:
        country_code = conf["country"]
        country_counters[country_code] += 1
        index = country_counters[country_code]
        
        new_name = get_rename_tag(country_code, index)
        
        if conf["protocol"] == "vmess":
            renamed_raw = rename_vmess_config(conf["raw"], new_name)
        else:
            renamed_raw = rename_non_vmess_config(conf["raw"], new_name)
            
        renamed_lines.append(renamed_raw)
        
    # --- ОФОРМЛЕНИЕ ПОДПИСКИ С КРАСИВЫМ ТРАФИКОМ И ОПИСАНИЕМ ---
    header_comments = [
        "#profile-title: base64:TUZITCBDb25uZWN0",  # MFHL Connect в Base64
        "#profile-update-interval: 12",
        "#subscription-userinfo: upload=0; download=0; total=1073741824000; expire=1893014400",
        "#support-url: https://t.me/LetoVPN_free",  # Кликабельная кнопка-самолетик (например, ведет в Лето VPN)
        # Описание под шкалой трафика (строго по вашему запросу, без кринжа)
        "#announce: 🛡️ MFHL Connect | Твой мост в свободный интернет без цензуры",
        "#description: 🛡️ MFHL Connect | Твой мост в свободный интернет без цензуры"
    ]
    
    all_output_lines = header_comments + renamed_lines
    
    stats = defaultdict(int)
    for f in final_selection:
        stats[f['country']] += 1
        
    print("\n[+] Распределение стран в финальной подписке (всего записей: {}):".format(len(final_selection)))
    for country, count in stats.items():
        print(f"    - {country}: {count} шт.")
        
    with open("subscription.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(all_output_lines))
    print("\n[+] Файл 'subscription.txt' успешно перезаписан с красивым оформлением.")
    
    base64_content = base64.b64encode("\n".join(all_output_lines).encode("utf-8")).decode("utf-8")
    with open("subscription_base64.txt", "w", encoding="utf-8") as f:
        f.write(base64_content)
    print("[+] Файл 'subscription_base64.txt' успешно перезаписан с красивым оформлением.")

def scheduler_loop():
    interval = 1800
    while True:
        try:
            print(f"\n{'='*50}")
            print(f"[*] Запуск цикла обновления: {time.strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"{'='*50}")
            run_aggregation()
            print(f"\n[*] Цикл завершен. Следующее обновление через 30 минут ({interval} сек)...")
        except Exception as e:
            print(f"[-] Произошла критическая ошибка в планировщике: {e}")
        time.sleep(interval)

if __name__ == "__main__":
    try:
        run_aggregation() # Одноразовый запуск для GitHub Actions
    except KeyboardInterrupt:
        print("\n[*] Работа сборщика остановлена пользователем.")
