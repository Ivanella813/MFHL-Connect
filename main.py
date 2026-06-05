import base64
import json
import re
import socket
import urllib.request
import urllib.parse
import html
import time
import os
import ssl
import random
import threading
from collections import defaultdict
from urllib.parse import urlparse, unquote, quote
from concurrent.futures import ThreadPoolExecutor, as_completed

# =====================================================================
# НАСТРОЙКА ЗАПУСКА
# =====================================================================
RUN_ON_LOCAL_RU_PC = False

# Режим GitHub Actions — более агрессивные настройки
IS_GITHUB_ACTIONS = os.getenv("GITHUB_ACTIONS", "false").lower() == "true"

# =====================================================================
# СЛОВАРЬ СТРАН
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
    "LT": {"flag": "🇱🇹", "ru_name": "Литва"},
}

LOCAL_FILE = "local_configs.txt"

RAW_URLS = [
    "https://mifa.world/other",
    "https://sub.fawlok.me/",
]

CONFIG_REGEX = re.compile(r'(?:vless|vmess|ss|trojan|hysteria2|tuic)://[^\s"<]+')

GEOIP_CACHE = {}
geoip_calls_count = 0
# В GitHub Actions увеличиваем лимит GeoIP — нет риска блока по IP
MAX_GEOIP_CALLS = 80 if IS_GITHUB_ACTIONS else 40

GLOBALPING_TOKEN = os.getenv("GLOBALPING_TOKEN", "")
CHECK_HOST_LOCK = threading.Lock()
RATE_LIMITED = False
globalping_tests_count = 0

# В GitHub Actions проверка из РФ через внешние API — основной метод
# Лимит увеличен, т.к. локальная проверка невозможна
MAX_GLOBALPING_TESTS_PER_RUN = 300 if IS_GITHUB_ACTIONS else 210

# =====================================================================
# СПИСОК ЗАВЕДОМО НЕРАБОЧИХ ИЗ РФ IP-ДИАПАЗОНОВ (Microsoft Azure)
# GitHub Actions использует Azure — многие серверы его блокируют
# Эти подсети часто блокируются российскими серверами в ответ
# =====================================================================
# Не фильтруем по IP Actions — наоборот, доверяем внешним проверкам

def decode_if_base64(text):
    clean_text = text.strip()
    normalized_text = re.sub(r'\s+', '', clean_text)
    if (re.match(r'^[A-Za-z0-9+/=\-_]+$', normalized_text)
            and not normalized_text.startswith("vless://")
            and not normalized_text.startswith("vmess://")
            and len(normalized_text) > 40):
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
                f.write("# Вставьте сюда конфиги или base64 подписку\n")
        except Exception:
            pass
        return []
    try:
        with open(LOCAL_FILE, "r", encoding="utf-8") as f:
            content = f.read()
            content = decode_if_base64(content)
            configs = CONFIG_REGEX.findall(content)
            if configs:
                print(f"[+] Из файла {LOCAL_FILE} извлечено {len(configs)} конфигураций.")
            return configs
    except Exception as e:
        print(f"[-] Ошибка при чтении {LOCAL_FILE}: {e}")
        return []


def fetch_raw_url(url):
    """Загружает URL с несколькими попытками и увеличенным таймаутом."""
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    
    for attempt in range(3):
        try:
            req = urllib.request.Request(url, headers=headers)
            timeout = 20 if IS_GITHUB_ACTIONS else 10
            with urllib.request.urlopen(req, timeout=timeout) as response:
                content = response.read().decode('utf-8', errors='ignore')
                content = decode_if_base64(content)
                configs = CONFIG_REGEX.findall(content)
                print(f"[+] {url[:60]}... -> {len(configs)} конфигураций.")
                return configs
        except Exception as e:
            if attempt < 2:
                time.sleep(2 * (attempt + 1))
            else:
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
                net_type = data.get("net", "").lower()
                is_ws = net_type == "ws"
                is_grpc = net_type == "grpc"
                is_httpupgrade = net_type == "httpupgrade"
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
                    "is_grpc": is_grpc,
                    "is_httpupgrade": is_httpupgrade,
                    "is_reality": False,
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
            is_reality = False
            is_grpc = False
            is_httpupgrade = False

            if parsed.query:
                try:
                    params = dict(
                        x.split("=", 1) for x in parsed.query.split("&") if "=" in x
                    )
                    security = params.get("security", "").lower()
                    if security in ["tls", "reality"]:
                        is_tls = True
                    if security == "reality":
                        is_reality = True
                    sni = params.get("sni")
                    transport_type = params.get("type", "").lower()
                    if transport_type == "ws":
                        is_ws = True
                    elif transport_type == "grpc":
                        is_grpc = True
                    elif transport_type == "httpupgrade":
                        is_httpupgrade = True
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
                "is_grpc": is_grpc,
                "is_httpupgrade": is_httpupgrade,
                "is_reality": is_reality,
                "path": path,
                "host_header": host_header,
                "raw": config_str
            }
    except Exception:
        pass
    return None


def get_backend_fingerprint(parsed):
    protocol = parsed["protocol"]
    credentials = parsed.get("credentials", "")
    host = parsed["host"]
    port = parsed["port"]
    sni = parsed.get("sni")
    path = parsed.get("path", "/")
    raw_lower = parsed.get("raw", "").lower()
    is_cdn = parsed.get("is_ws") or "grpc" in raw_lower or "httpupgrade" in raw_lower
    if is_cdn and sni:
        return (protocol, credentials, sni.lower(), path)
    else:
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
        "🇧🇷": "BR", "🇿🇦": "ZA", "🇱🇹": "LT",
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
        "IL": r"\b(IL|ISR|ISRAEL|ИЗРАИЛЬ)\b",
        "HU": r"\b(HU|HUN|HUNGARY|ВЕНГРИЯ)\b",
        "CZ": r"\b(CZ|CZE|CZECH|ЧЕХИЯ|ПРАГА)\b",
        "IN": r"\b(IN|IND|INDIA|ИНДИЯ)\b",
    }
    for country, pattern in patterns.items():
        if re.search(pattern, name_upper):
            return country
    return None


def test_websocket_node(ip, port, is_tls, host, path, host_header=None, timeout=3.0):
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


def test_node_connection(host, port, protocol, is_tls=False, sni=None,
                         is_ws=False, path=None, host_header=None, timeout=3.0):
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
                    ssl_sock.getpeercert()
                    return ip
        except Exception:
            return None

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
        timeout=3.0
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

    # Список GeoIP провайдеров — пробуем по очереди
    providers = [
        _geoip_freeipapi,
        _geoip_ipapi,
        _geoip_ipinfo,
    ]
    random.shuffle(providers)  # Ротация для снижения нагрузки на один сервис

    for provider in providers:
        result = provider(ip)
        if result and result != "Unknown":
            GEOIP_CACHE[ip] = result
            geoip_calls_count += 1
            return result

    return "Unknown"


def _geoip_freeipapi(ip):
    try:
        url = f"https://freeipapi.com/api/json/{ip}"
        req = urllib.request.Request(
            url, headers={"User-Agent": "Mozilla/5.0"}
        )
        with urllib.request.urlopen(req, timeout=4) as response:
            data = json.loads(response.read().decode('utf-8'))
            return data.get("countryCode", "Unknown")
    except Exception:
        return None


def _geoip_ipapi(ip):
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,countryCode"
        req = urllib.request.Request(
            url, headers={"User-Agent": "Mozilla/5.0"}
        )
        with urllib.request.urlopen(req, timeout=4) as response:
            data = json.loads(response.read().decode('utf-8'))
            if data.get("status") == "success":
                time.sleep(1.2)  # Rate limit ip-api.com (45 req/min)
                return data.get("countryCode", "Unknown")
    except Exception:
        pass
    return None


def _geoip_ipinfo(ip):
    try:
        token = os.getenv("IPINFO_TOKEN", "")
        url = f"https://ipinfo.io/{ip}/json"
        if token:
            url += f"?token={token}"
        req = urllib.request.Request(
            url, headers={"User-Agent": "Mozilla/5.0"}
        )
        with urllib.request.urlopen(req, timeout=4) as response:
            data = json.loads(response.read().decode('utf-8'))
            return data.get("country", "Unknown")
    except Exception:
        return None


# =====================================================================
# CHECK-HOST — проверка доступности из РФ
# =====================================================================
def test_port_from_russia_check_host(host, port, timeout=15):
    """
    Проверяет доступность хоста из российских нод через check-host.net.
    Использует несколько российских нод для надёжности.
    """
    # Используем несколько РФ-нод
    target_nodes = [
        "ru2.node.check-host.net",
        "ru4.node.check-host.net",
        "ru6.node.check-host.net",
    ]
    base_url = "https://check-host.net/check-tcp"
    query_params = [("host", f"{host}:{port}")]
    for node in target_nodes:
        query_params.append(("node", node))
    url = f"{base_url}?{urllib.parse.urlencode(query_params)}"
    headers = {
        "Accept": "application/json",
        "User-Agent": "Mozilla/5.0",
    }
    request_id = None
    with CHECK_HOST_LOCK:
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=6) as r:
                res = json.loads(r.read().decode('utf-8'))
                request_id = res.get("request_id")
        except Exception as e:
            pass
        time.sleep(2.0)

    if not request_id:
        return None

    poll_url = f"https://check-host.net/check-result/{request_id}"
    start_time = time.time()

    while time.time() - start_time < timeout:
        try:
            time.sleep(2.5)
            poll_req = urllib.request.Request(poll_url, headers=headers)
            with urllib.request.urlopen(poll_req, timeout=5) as pr:
                poll_res = json.loads(pr.read().decode('utf-8'))
                if not isinstance(poll_res, dict):
                    continue

                successes = 0
                failures = 0
                pending = 0

                for node in target_nodes:
                    node_res = poll_res.get(node)
                    if node_res is None:
                        pending += 1
                        continue
                    # null означает "нода ещё работает"
                    if node_res is None:
                        pending += 1
                        continue
                    node_ok = False
                    for item in node_res:
                        if isinstance(item, list) and len(item) > 0:
                            if item[0] == 1:
                                node_ok = True
                                break
                    if node_ok:
                        successes += 1
                    else:
                        failures += 1

                # Достаточно 1 успешной проверки из РФ
                if successes >= 1:
                    return True
                # Все ноды ответили отказом
                if pending == 0 and failures > 0 and successes == 0:
                    return False
        except Exception:
            pass
    return None


# =====================================================================
# GLOBALPING — резервная проверка из РФ
# =====================================================================
def test_port_from_russia_globalping(host, port, timeout=15,
                                     is_tls=True, sni=None, host_header=None):
    global RATE_LIMITED, globalping_tests_count
    if RATE_LIMITED:
        return None
    if globalping_tests_count >= MAX_GLOBALPING_TESTS_PER_RUN:
        RATE_LIMITED = True
        return None

    url = "https://api.globalping.io/v1/measurements"
    limit_probes = 2
    req_host = sni if sni else (host_header if host_header else host)
    locations = [{"magic": "RU"}]

    if is_tls:
        payload = {
            "type": "http",
            "target": host,
            "locations": locations,
            "limit": limit_probes,
            "measurementOptions": {
                "port": int(port),
                "protocol": "HTTPS",
                "request": {"method": "GET", "path": "/", "host": req_host},
            },
        }
    else:
        payload = {
            "type": "ping",
            "target": host,
            "locations": locations,
            "limit": limit_probes,
            "measurementOptions": {
                "protocol": "TCP",
                "port": int(port),
                "packets": 2,
            },
        }

    headers = {"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"}
    if GLOBALPING_TOKEN:
        headers["Authorization"] = f"Bearer {GLOBALPING_TOKEN}"

    try:
        globalping_tests_count += limit_probes
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode('utf-8'),
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=6) as r:
            res = json.loads(r.read().decode('utf-8'))
            m_id = res.get("id")
            if not m_id:
                return None

        poll_url = f"https://api.globalping.io/v1/measurements/{m_id}"
        start_time = time.time()
        poll_headers = {"User-Agent": headers["User-Agent"]}
        if GLOBALPING_TOKEN:
            poll_headers["Authorization"] = headers["Authorization"]

        while time.time() - start_time < timeout:
            time.sleep(2.0)
            poll_req = urllib.request.Request(poll_url, headers=poll_headers)
            try:
                with urllib.request.urlopen(poll_req, timeout=5) as pr:
                    poll_res = json.loads(pr.read().decode('utf-8'))
                    status = poll_res.get("status")
                    if status == "finished":
                        results = poll_res.get("results", [])
                        if not results:
                            return None
                        success_count = 0
                        for r_item in results:
                            probe_result = r_item.get("result", {})
                            if is_tls:
                                status_code = probe_result.get("statusCode")
                                if isinstance(status_code, int) and status_code > 0:
                                    success_count += 1
                            else:
                                if probe_result.get("status") != "failed":
                                    stats = probe_result.get("stats", {})
                                    loss = stats.get("loss", 100)
                                    if loss < 100:
                                        success_count += 1
                        return success_count > 0
                    elif status == "failed":
                        return False
            except urllib.error.HTTPError as e:
                if e.code == 429:
                    print(" [!] Globalping: HTTP 429 — лимит исчерпан.")
                    RATE_LIMITED = True
                    return None
            except Exception:
                pass
        return None

    except urllib.error.HTTPError as e:
        if e.code == 429:
            print(" [!] Globalping API: HTTP 429.")
            RATE_LIMITED = True
        return None
    except Exception:
        return None


# =====================================================================
# ПРОВЕРКА ИЗ РФ — КОМБИНИРОВАННАЯ СТРАТЕГИЯ
# =====================================================================
def check_ru_accessibility_worker(conf):
    """
    Стратегия проверки адаптирована под среду запуска:

    GitHub Actions (IS_GITHUB_ACTIONS=True):
      - Локальная TCP/TLS проверка уже пройдена на предыдущем этапе
      - Дополнительно проверяем через Check-Host (российские ноды)
      - Резерв: Globalping с локацией RU
      - Если оба API недоступны — сохраняем конфиг (лучше лишний, чем пропустить рабочий)

    Локальный ПК в РФ (RUN_ON_LOCAL_RU_PC=True):
      - Локальная проверка = проверка из РФ, внешние API не нужны
    """
    if RUN_ON_LOCAL_RU_PC:
        return conf

    protocol = conf.get("protocol", "").lower()

    # QUIC-протоколы нельзя проверить через TCP-based API
    if protocol in ["hysteria2", "tuic"]:
        print(f"    [~] {protocol}://{conf['host']}:{conf['port']} — QUIC, пропускаем проверку из РФ.")
        return conf

    host = conf["host"]
    port = conf["port"]
    is_tls = conf.get("is_tls", False)
    sni = conf.get("sni")
    host_header = conf.get("host_header")
    country = conf.get("country", "?")

    # --- Шаг 1: Check-Host ---
    ch_result = test_port_from_russia_check_host(host, port)

    if ch_result is True:
        print(f"    [✓] CheckHost RU OK: {host}:{port} ({country})")
        return conf
    elif ch_result is False:
        print(f"    [✗] CheckHost RU BLOCK: {host}:{port} ({country})")
        return None
    # ch_result is None — API недоступен или таймаут

    # --- Шаг 2: Globalping ---
    gp_result = test_port_from_russia_globalping(
        host, port, is_tls=is_tls, sni=sni, host_header=host_header
    )

    if gp_result is True:
        print(f"    [✓] Globalping RU OK: {host}:{port} ({country})")
        return conf
    elif gp_result is False:
        print(f"    [✗] Globalping RU BLOCK: {host}:{port} ({country})")
        return None

    # --- Шаг 3: Оба API не дали ответа ---
    # В GitHub Actions лучше сохранить сомнительный конфиг,
    # чем потерять рабочий из-за перегрузки API
    print(f"    [?] Нет данных из РФ для {host}:{port} ({country}) — сохранён.")
    return conf


def get_rename_tag(country_code, index):
    info = COUNTRY_INFO.get(country_code)
    if info:
        return f"{info['flag']} {info['ru_name']} #{index}"
    if (len(country_code) == 2
            and country_code not in ("UN", "Unknown")):
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
# ДВУХЭТАПНАЯ ПРОВЕРКА
# =====================================================================
def verify_configs_optimized(raw_configs, max_workers=30,
                              selected_by_country=None):
    if not raw_configs:
        return []

    # Этап 1: глобальная TCP/TLS доступность (параллельно)
    alive_globally = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(check_tls_or_tcp_worker, r): r
                   for r in raw_configs}
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

    # Дедупликация по (host, port)
    seen = set()
    deduped_alive = []
    for conf in alive_globally:
        key = (conf["host"], conf["port"])
        if key not in seen:
            seen.add(key)
            deduped_alive.append(conf)
    alive_globally = deduped_alive

    # GeoIP обогащение
    for conf in alive_globally:
        country = get_country_code(conf["ip"], conf["name"])
        conf["country"] = country

    # Фильтрация по лимиту страны
    filtered_candidates = []
    if selected_by_country:
        for conf in alive_globally:
            country = conf["country"]
            if len(selected_by_country[country]) < 5:
                filtered_candidates.append(conf)
    else:
        filtered_candidates = alive_globally

    if not filtered_candidates:
        return []

    mode = "Локальный РФ ПК" if RUN_ON_LOCAL_RU_PC else "GitHub Actions / удалённый"
    print(f"[*] Глобально живых: {len(alive_globally)} | "
          f"После фильтра стран: {len(filtered_candidates)} | Режим: {mode}")

    if RUN_ON_LOCAL_RU_PC:
        return filtered_candidates

    # Этап 2: проверка из РФ (последовательно — check-host не любит параллельность)
    print(f"[*] Проверка {len(filtered_candidates)} узлов из РФ...")
    verified = []

    # В GitHub Actions можно немного распараллелить Globalping,
    # но Check-Host требует lock — поэтому workers=3 как компромисс
    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = {executor.submit(check_ru_accessibility_worker, conf): conf
                   for conf in filtered_candidates}
        for future in as_completed(futures):
            try:
                res = future.result()
                if res:
                    verified.append(res)
            except Exception:
                pass

    return verified


# =====================================================================
# ОСНОВНАЯ ЛОГИКА АГРЕГАЦИИ
# =====================================================================
def run_aggregation():
    global geoip_calls_count, RATE_LIMITED, globalping_tests_count

    geoip_calls_count = 0
    RATE_LIMITED = False
    globalping_tests_count = 0

    selected_by_country = defaultdict(list)
    selected_raws = set()
    selected_fingerprints = set()

    env_info = "GitHub Actions" if IS_GITHUB_ACTIONS else "Локальный"
    print(f"[*] Режим запуска: {env_info}")
    print(f"[*] Лимит GeoIP: {MAX_GEOIP_CALLS} | "
          f"Лимит Globalping: {MAX_GLOBALPING_TESTS_PER_RUN}")

    # --- Загрузка старой подписки ---
    old_configs = []
    if os.path.exists("subscription.txt"):
        try:
            with open("subscription.txt", "r", encoding="utf-8") as f:
                content = f.read()
                old_configs = CONFIG_REGEX.findall(content)
        except Exception:
            pass

    if old_configs:
        unique_old = deduplicate_raw_configs(list(set(old_configs)))
        print(f"[*] Старых уникальных конфигов: {len(unique_old)}")
        random.shuffle(unique_old)
        alive_old = verify_configs_optimized(
            unique_old, selected_by_country=selected_by_country
        )
        for conf in alive_old:
            country = conf["country"]
            parsed = parse_config(conf["raw"])
            fp = get_backend_fingerprint(parsed) if parsed else None
            if (fp and fp not in selected_fingerprints
                    and len(selected_by_country[country]) < 5
                    and len(selected_raws) < 50):
                selected_by_country[country].append(conf)
                selected_raws.add(conf["raw"])
                selected_fingerprints.add(fp)
                print(f"    [+] Старый рабочий: "
                      f"{conf['protocol']}://{conf['host']}:{conf['port']} ({country})")

    total_selected = len(selected_raws)
    print(f"[*] После проверки старой подписки: {total_selected}/50 узлов.")

    # --- Добор новых конфигов ---
    if total_selected < 50:
        print("[*] Сбор новых конфигураций...")
        new_raw_configs = []
        new_raw_configs.extend(fetch_local_file())

        # Параллельная загрузка источников
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {executor.submit(fetch_raw_url, url): url
                       for url in RAW_URLS}
            for future in as_completed(futures):
                try:
                    new_raw_configs.extend(future.result())
                except Exception:
                    pass

        all_new_raws = list(set(new_raw_configs) - selected_raws)
        all_new_raws = deduplicate_raw_configs(all_new_raws)

        # Фильтрация уже выбранных fingerprint
        all_new_raws = [
            raw for raw in all_new_raws
            if (lambda p: p and get_backend_fingerprint(p) not in selected_fingerprints)(
                parse_config(raw)
            )
        ]

        random.shuffle(all_new_raws)
        print(f"[*] Новых уникальных кандидатов: {len(all_new_raws)}")

        batch_size = 20
        test_queue_index = 0

        while test_queue_index < len(all_new_raws) and len(selected_raws) < 50:
            batch = []
            while len(batch) < batch_size and test_queue_index < len(all_new_raws):
                raw_conf = all_new_raws[test_queue_index]
                test_queue_index += 1
                parsed = parse_config(raw_conf)
                if not parsed:
                    continue
                est_country = detect_country_from_name(parsed["name"])
                if est_country and len(selected_by_country[est_country]) >= 5:
                    continue
                batch.append(raw_conf)

            if not batch:
                break

            print(f"[*] Пачка {test_queue_index // batch_size}: "
                  f"{len(batch)} кандидатов...")
            verified_batch = verify_configs_optimized(
                batch, selected_by_country=selected_by_country
            )

            for conf in verified_batch:
                country = conf["country"]
                parsed = parse_config(conf["raw"])
                fp = get_backend_fingerprint(parsed) if parsed else None
                if (fp and fp not in selected_fingerprints
                        and len(selected_by_country[country]) < 5
                        and len(selected_raws) < 50):
                    selected_by_country[country].append(conf)
                    selected_raws.add(conf["raw"])
                    selected_fingerprints.add(fp)
                    print(f"    [+] Новый: "
                          f"{conf['protocol']}://{conf['host']}:{conf['port']} ({country})")

    # --- Финальное переименование и сохранение ---
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

    header_comments = [
        "#profile-title: base64:TUZITCBDb25uZWN0",
        "#profile-update-interval: 12",
        "#subscription-userinfo: upload=0; download=0; total=1073741824000; expire=1893014400",
        "#support-url: https://t.me/Amirka_TG",
        "#announce: 🛡️ MFHL Connect | Твой мост в свободный интернет без цензуры",
        "#description: 🛡️ MFHL Connect | Твой мост в свободный интернет без цензуры",
    ]
    all_output_lines = header_comments + renamed_lines

    stats = defaultdict(int)
    for f in final_selection:
        stats[f['country']] += 1
    print(f"\n[+] Итого в подписке: {len(final_selection)} серверов")
    for country, count in sorted(stats.items(), key=lambda x: -x[1]):
        info = COUNTRY_INFO.get(country, {})
        flag = info.get("flag", "🌐")
        name = info.get("ru_name", country)
        print(f"    {flag} {name}: {count} шт.")

    with open("subscription.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(all_output_lines))
    print("\n[+] subscription.txt сохранён.")

    b64 = base64.b64encode(
        "\n".join(all_output_lines).encode("utf-8")
    ).decode("utf-8")
    with open("subscription_base64.txt", "w", encoding="utf-8") as f:
        f.write(b64)
    print("[+] subscription_base64.txt сохранён.")


if __name__ == "__main__":
    try:
        run_aggregation()
    except KeyboardInterrupt:
        print("\n[*] Остановлено пользователем.")
