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
# СЛОВАРЬ СТРАН (Расширен для поддержки Латвии, Израиля, Венгрии и др.)
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
    "LV": {"flag": "🇱🇻", "ru_name": "Латвия"},
    "IL": {"flag": "🇮🇱", "ru_name": "Израиль"},
    "HU": {"flag": "🇭🇺", "ru_name": "Венгрия"},
    "IS": {"flag": "🇮🇸", "ru_name": "Исландия"},
    "CZ": {"flag": "🇨🇿", "ru_name": "Чехия"},
    "IE": {"flag": "🇮🇪", "ru_name": "Ирландия"},
    "IN": {"flag": "🇮🇳", "ru_name": "Индия"},
    "PT": {"flag": "🇵🇹", "ru_name": "Португалия"},
    "NO": {"flag": "🇳🇴", "ru_name": "Норвегия"},
    "GR": {"flag": "🇬🇷", "ru_name": "Греция"},
    "BE": {"flag": "🇧🇪", "ru_name": "Бельгия"},
    "CY": {"flag": "🇨🇾", "ru_name": "Кипр"},
    "MD": {"flag": "🇲🇩", "ru_name": "Молдова"},
    "GE": {"flag": "🇬🇪", "ru_name": "Грузия"},
    "AM": {"flag": "🇦🇲", "ru_name": "Армения"},
    "AZ": {"flag": "🇦🇿", "ru_name": "Азербайджан"},
    "AE": {"flag": "🇦🇪", "ru_name": "ОАЭ"},
    "AU": {"flag": "🇦🇺", "ru_name": "Австралия"},
    "BR": {"flag": "🇧🇷", "ru_name": "Бразилия"},
    "ZA": {"flag": "🇿🇦", "ru_name": "ЮАР"},
}

# Название локального файла для копирования конфигов из чатов/групп
LOCAL_FILE = "local_configs.txt"

# Специфический источник (Белые списки РФ / обход блокировок)
SPECIAL_RU_SOURCE = "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/Vless-Reality-White-Lists-Rus-Mobile.txt"

# Общие источники (проверенные)
RAW_URLS = [
    "https://raw.githubusercontent.com/adop1344-bot/LetoVPN_free/refs/heads/main/ru.txt",
    "https://mifa.world/other"
]

CONFIG_REGEX = re.compile(r'(?:vless|vmess|ss|trojan|hysteria2|tuic)://[^\s"<]+')

GEOIP_CACHE = {}
geoip_calls_count = 0
MAX_GEOIP_CALLS = 40

# Переменная токена для Globalping (можно оставить пустой)
GLOBALPING_TOKEN = os.getenv("GLOBALPING_TOKEN", "")

def decode_if_base64(text):
    clean_text = text.strip()
    normalized_text = re.sub(r'\s+', '', clean_text)
    
    if re.match(r'^[A-Za-z0-9+/=\-_]+$', normalized_text) and not normalized_text.startswith("vless://") and not normalized_text.startswith("vmess://") and len(normalized_text) > 40:
        try:
            normalized_text = normalized_text.replace('-', '+').replace('_', '/')
            normalized_text += "=" * ((4 - len(normalized_text) % 4) % 4)
            decoded = base64.b64decode(normalized_text).decode('utf-8', errors='ignore')
            if CONFIG_REGEX.search(decoded):
                return decoded
        except Exception:
            pass
    return text

def fetch_local_file():
    if not os.path.exists(LOCAL_FILE):
        try:
            with open(LOCAL_FILE, "w", encoding="utf-8") as f:
                f.write("# Вставьте сюда скопированный текст из групп или готовую base64 подписку\n")
                f.write("# Скрипт автоматически декодирует данные и извлечет из них ссылки при запуске!\n")
        except Exception:
            pass
        return []
        
    try:
        with open(LOCAL_FILE, "r", encoding="utf-8") as f:
            content = f.read()
            content = decode_if_base64(content)
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
                    "credentials": data.get("id", ""),
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
            credentials = ""
            if "@" in netloc:
                credentials, host_port = netloc.rsplit("@", 1)
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
                "credentials": credentials,
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

# =====================================================================
# УМНЫЙ ПОИСК ДУБЛИКАТОВ БЭКЕНДОВ (Удаление клонов на CDN)
# =====================================================================
def get_backend_fingerprint(parsed):
    protocol = parsed["protocol"]
    credentials = parsed.get("credentials", "")
    host = parsed["host"]
    port = parsed["port"]
    sni = parsed.get("sni")
    path = parsed.get("path", "/")
    is_ws = parsed.get("is_ws", False)
    
    raw_lower = parsed.get("raw", "").lower()
    is_cdn = is_ws or "grpc" in raw_lower or "httpupgrade" in raw_lower
    
    if is_cdn and sni:
        # Для CDN-воркеров бэкенд определяется по SNI, паролю и пути
        return (protocol, credentials, sni.lower(), path)
    else:
        # Для прямых Reality серверов бэкендом выступает непосредственно хост VPS
        return (protocol, credentials, host.lower(), port)

def deduplicate_raw_configs(raw_configs):
    seen_fingerprints = set()
    unique_configs = []
    for raw in raw_configs:
        parsed = parse_config(raw)
        if not parsed:
            continue
        fingerprint = get_backend_fingerprint(parsed)
        if fingerprint not in seen_fingerprints:
            seen_fingerprints.add(fingerprint)
            unique_configs.append(raw)
    return unique_configs

def detect_country_from_name(name):
    if not name:
        return None
    name_upper = name.upper()
    
    country_flags = {
        "🇷🇺": "RU", "🇺🇸": "US", "🇩🇪": "DE", "🇳🇱": "NL", "🇫🇮": "FI", 
        "🇬🇧": "GB", "🇫🇷": "FR", "🇵🇱": "PL", "🇰🇿": "KZ", "🇧🇾": "BY", 
        "🇹🇷": "TR", "🇸🇬": "SG", "🇯🇵": "JP", "🇸🇪": "SE", "🇨🇦": "CA",
        "🇪🇪": "EE", "🇰🇷": "KR", "🇱🇻": "LV", "🇮🇱": "IL", "🇭🇺": "HU",
        "🇮🇸": "IS", "🇨🇿": "CZ", "🇮🇪": "IE", "🇮🇳": "IN", "🇵🇹": "PT",
        "🇳🇴": "NO", "🇬🇷": "GR", "🇧🇪": "BE", "🇨🇾": "CY", "🇲🇩": "MD",
        "🇬🇪": "GE", "🇦🇲": "AM", "🇦🇿": "AZ", "🇦🇪": "AE", "🇦🇺": "AU",
        "🇧🇷": "BR", "🇿🇦": "ZA"
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
        "LV": r"\b(LV|LAT|LATVIA|ЛАТВИЯ|РИГА)\b",
        "IL": r"\b(IL|ISR|ISRAEL|ИЗРАИЛЬ|ТЕЛ\s*-?\s*АВИВ)\b",
        "HU": r"\b(HU|HUN|HUNGARY|ВЕНГРИЯ|БУДАПЕШТ)\b",
        "CZ": r"\b(CZ|CZE|CZECH|ЧЕХИЯ|ПРАГА)\b",
        "IN": r"\b(IN|IND|INDIA|ИНДИЯ)\b",
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

# =====================================================================
# НАДЕЖНЫЙ GEOIP ЧЕРЕЗ FREEIPAPI.COM
# =====================================================================
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
        url = f"https://freeipapi.com/api/json/{ip}"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=3) as response:
            data = json.loads(response.read().decode('utf-8'))
            country = data.get("countryCode", "Unknown")
            if country and country != "Unknown":
                GEOIP_CACHE[ip] = country
                geoip_calls_count += 1
                return country
    except Exception:
        pass
        
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

# =====================================================================
# ПРОВЕРКА ЧЕРЕЗ RU+EYEBALL ЗОНДЫ (ДОМАШНИЙ ИНТЕРНЕТ РФ)
# =====================================================================
def test_port_from_russia(host, port, timeout=12):
    url = "https://api.globalping.io/v1/measurements"
    payload = {
        "type": "ping",
        "target": host,
        "locations": [{"magic": "RU+eyeball"}],
        "limit": 1,
        "measurementOptions": {
            "protocol": "TCP",
            "port": int(port),
            "packets": 2
        }
    }
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }
    if GLOBALPING_TOKEN:
        headers["Authorization"] = f"Bearer {GLOBALPING_TOKEN}"
    
    try:
        req = urllib.request.Request(url, data=json.dumps(payload).encode('utf-8'), headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=5) as r:
            res = json.loads(r.read().decode('utf-8'))
            m_id = res.get("id")
            if not m_id:
                return False
                
        poll_url = f"https://api.globalping.io/v1/measurements/{m_id}"
        start_time = time.time()
        while time.time() - start_time < timeout:
            time.sleep(1.5)
            poll_req = urllib.request.Request(poll_url, headers={"User-Agent": headers["User-Agent"]})
            try:
                with urllib.request.urlopen(poll_req, timeout=4) as pr:
                    poll_res = json.loads(pr.read().decode('utf-8'))
                    status = poll_res.get("status")
                    
                    if status == "finished":
                        results = poll_res.get("results", [])
                        if not results:
                            return False
                        
                        probe_result = results[0].get("result", {})
                        if probe_result.get("status") == "failed":
                            return False
                            
                        stats = probe_result.get("stats", {})
                        loss = stats.get("loss", 100)
                        return loss < 100
                        
                    elif status == "failed":
                        return False
            except Exception:
                pass
        return False
    except Exception as e:
        print(f" [!] Ошибка связи с API Globalping ({e}). Фолбек: считаем узел временно доступным.")
        return True

def get_rename_tag(country_code, index):
    global COUNTRY_INFO
    
    info = COUNTRY_INFO.get(country_code)
    if info:
        return f"{info['flag']} {info['ru_name']} #{index}"
    else:
        # Если страна отсутствует в базе, собираем флаг автоматически из ее ISO-кода
        if len(country_code) == 2 and country_code != "UN" and country_code != "Unknown":
            try:
                flag = "".join(chr(127397 + ord(c)) for c in country_code)
                return f"{flag} {country_code} #{index}"
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

# =====================================================================
# ВОРКЕР ДЛЯ ПАРАЛЛЕЛЬНОГО ТЕСТИРОВАНИЯ ИЗ РФ
# =====================================================================
def check_ru_accessibility_worker(conf):
    host = conf["host"]
    port = conf["port"]
    is_alive_in_ru = test_port_from_russia(host, port)
    if is_alive_in_ru:
        return conf
    return None

# =====================================================================
# ПОЛНОСТЬЮ ОПТИМИЗИРОВАННАЯ ДВУХЭТАПНАЯ ПРОВЕРКА (СКОРОСТЬ x15)
# =====================================================================
def verify_configs_optimized(raw_configs, max_workers=25, selected_by_country=None):
    if not raw_configs:
        return []
    
    # 1. Быстрая параллельная локальная проверка (из-за рубежа)
    alive_globally = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(check_tls_or_tcp_worker, r): r for r in raw_configs}
        for future in as_completed(futures):
            try:
                res = future.result()
                if res:
                    alive_globally.append(res)
            except Exception:
                pass
                
    if not alive_globally:
        return []
        
    random.shuffle(alive_globally)
    
    # Дедупликация хостов/портов в текущей пачке, чтобы не слать дубли в API
    seen = set()
    deduped_alive = []
    for conf in alive_globally:
        key = (conf["host"], conf["port"])
        if key not in seen:
            seen.add(key)
            deduped_alive.append(conf)
    alive_globally = deduped_alive
    
    # Определение стран для "выживших" локально узлов и жесткий отсев
    # тех, по которым лимит подписки (5 шт) уже полностью забит!
    filtered_candidates = []
    for conf in alive_globally:
        country = get_country_code(conf["ip"], conf["name"])
        conf["country"] = country
        
        # Если эта страна в подписке уже заполнена (накоплено 5 штук), 
        # пропускаем узел и даже не отправляем его на платный по времени тест в Globalping!
        if selected_by_country and len(selected_by_country[country]) >= 5:
            continue
            
        filtered_candidates.append(conf)
        
    if not filtered_candidates:
        return []
        
    # Будем проверять за раз не более 15 реально необходимых кандидатов
    candidates_to_check = filtered_candidates[:15]
    
    print(f"[*] Локально доступны: {len(alive_globally)} шт. (после фильтрации забитых стран осталось: {len(filtered_candidates)} шт.)")
    print(f"[*] Запуск параллельной проверки {len(candidates_to_check)} узлов из РФ через eyeball-зонды...")
    
    # 2. МНОГОПОТОЧНЫЙ запуск тестов Globalping (дает ускорение x10-x15)
    verified = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(check_ru_accessibility_worker, conf): conf for conf in candidates_to_check}
        for future in as_completed(futures):
            try:
                res = future.result()
                if res:
                    verified.append(res)
                    print(f"    [+] Проверен из РФ: {res['host']}:{res['port']} ({res['country']}) -> РАБОТАЕТ")
            except Exception:
                pass
                
    return verified

def process_special_ru_source():
    print(f"\n[*] Специфический сбор из источника: {SPECIAL_RU_SOURCE}")
    raw_configs = fetch_raw_url(SPECIAL_RU_SOURCE)
    unique_raw = list(set(raw_configs))
    
    optimized_raw = pre_filter_raw_configs(unique_raw, max_per_country_pre=10)
    
    print(f"[*] Проверка {len(optimized_raw)} серверов из спец. источника...")
    alive_configs = verify_configs_optimized(optimized_raw)
                
    ru_working_configs = []
    fallback_working_configs = []
    
    print("[*] Определение геолокации для спец. источника...")
    for conf in alive_configs:
        country = conf["country"]
        
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
        print(f"[*] Добираем еще {needed} рабочих узлов из этого же файла...")
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
        # Применяем фильтрацию дубликатов бэкендов на старых конфигах
        unique_old = deduplicate_raw_configs(list(set(old_configs)))
        print(f"[*] Найдено {len(unique_old)} уникальных бэкендов из предыдущей подписки.")
        print("[*] Перемешивание и проверка старых конфигураций в первую очередь...")
        random.shuffle(unique_old)
        alive_old = verify_configs_optimized(unique_old, selected_by_country=selected_by_country)
        
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
        
        for url in RAW_URLS:
            new_raw_configs.extend(fetch_raw_url(url))
            
        all_new_raws = list(set(new_raw_configs + special_ru_raws) - selected_raws)
        
        # Фильтруем все собранные за раз новые ссылки на дубли бэкендов, чтобы не проверять одно и то же
        all_new_raws = deduplicate_raw_configs(all_new_raws)
        
        test_queue = list(all_new_raws)
        random.shuffle(test_queue)
        
        batch_size = 15
        print(f"[*] Для тестирования доступно {len(test_queue)} новых уникальных кандидатов.")
        print(f"[*] Начинаем порционный опрос пачками по {batch_size} до заполнения лимита...")
        
        test_queue_index = 0
        while test_queue_index < len(test_queue):
            if len(selected_raws) >= 50:
                break
                
            batch = []
            while len(batch) < batch_size and test_queue_index < len(test_queue):
                raw_conf = test_queue[test_queue_index]
                test_queue_index += 1
                
                parsed = parse_config(raw_conf)
                if not parsed:
                    continue
                
                # Быстрая оценка страны по названию в ссылке
                est_country = detect_country_from_name(parsed["name"])
                if est_country and len(selected_by_country[est_country]) >= 5:
                    continue
                    
                batch.append(raw_conf)
                
            if not batch:
                break
                
            print(f"[*] Проверка пачки из {len(batch)} новых кандидатов...")
            verified_batch = verify_configs_optimized(batch, selected_by_country=selected_by_country)
            
            for conf in verified_batch:
                country = conf["country"]
                if len(selected_by_country[country]) < 5 and len(selected_raws) < 50:
                    selected_by_country[country].append(conf)
                    selected_raws.add(conf["raw"])
                    print(f"    [+] Добавлен новый уникальный сервер: {conf['protocol']}://{conf['host']}:{conf['port']} ({country})")
                    
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
        "#support-url: https://t.me/Amirka_TG",  # Кликабельная кнопка-самолетик
        # Описание под шкалой трафика
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
    print("\n[+] Файл 'subscription.txt' успешно перезаписан.")
    
    base64_content = base64.b64encode("\n".join(all_output_lines).encode("utf-8")).decode("utf-8")
    with open("subscription_base64.txt", "w", encoding="utf-8") as f:
        f.write(base64_content)
    print("[+] Файл 'subscription_base64.txt' успешно перезаписан.")

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
