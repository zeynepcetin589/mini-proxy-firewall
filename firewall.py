import socket
from datetime import datetime
import time
from collections import defaultdict
import json
import argparse




with open("rules.json") as f:
    rules = json.load(f)

BLOCKED_IPS = set(rules["blocked_ips"])
BLOCKED_KEYWORDS = [k.encode() for k in rules["blocked_keywords"]]
BLOCKED_DOMAINS = set(rules.get("blocked_domains", []))
RATE_LIMIT = rules["rate_limit"]


parser = argparse.ArgumentParser()

parser.add_argument("--block-ip", help="Block an IP address")
parser.add_argument("--block-word", help="Block a keyword")
parser.add_argument("--rate-limit", type=int, help="Set new rate limit")

args = parser.parse_args()

def save_rules():
    with open("rules.json", "w") as f:
        json.dump({
            "blocked_ips": list(BLOCKED_IPS),
            "blocked_keywords": [k.decode() for k in BLOCKED_KEYWORDS],
            "blocked_domains": list(BLOCKED_DOMAINS),
            "rate_limit": RATE_LIMIT
        }, f, indent=4)


if args.block_ip:
    BLOCKED_IPS.add(args.block_ip)
    save_rules()

if args.block_word:
    BLOCKED_KEYWORDS.append(args.block_word.encode())
    save_rules()

if args.rate_limit:
    RATE_LIMIT = args.rate_limit
    save_rules()



LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 8888

TARGET_HOST = "example.com"
TARGET_PORT = 80

REQUESTS = defaultdict(list)
WINDOW = 10

LOG_FILE = "firewall.log"

def log(level, message):
    with open(LOG_FILE, "a") as f:
        f.write(f"[{datetime.now()}] [{level}] {message}\n")

def parse_http_request(data):
    try:
        text = data.decode(errors="ignore")
        lines = text.split("\r\n")

        headers = {}
        for line in lines[1:]:
            if ": " in line:
                key, value = line.split(": ", 1)
                headers[key.lower()] = value.strip()

        return headers
    except:
        return {}


def start_firewall():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((LISTEN_HOST, LISTEN_PORT))
    server.listen(5)

    print(f"Firewall running on {LISTEN_HOST}:{LISTEN_PORT}")

    while True:
        client, addr = server.accept()
        log("INFO", f"Connection from {addr}")
        print(f"Connection from {addr}")
        handle_client(client, addr)


def handle_client(client_socket,addr):
    remote = None

    while True:
        data = client_socket.recv(4096)
        if not data:
            break

        headers = parse_http_request(data)
        host = headers.get("host")

        if not host:
            client_socket.close()
            return

        if host in BLOCKED_DOMAINS:
            log("BLOCK", f"Blocked domain: {host}")
            client_socket.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\nBlocked domain")
            break

        if host in BLOCKED_DOMAINS:
            log("BLOCK", f"Blocked domain: {host}")
            client_socket.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\nBlocked domain")
            break

        if remote is None:
            remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote.connect((host, 80))

        if not is_allowed(data):
            log("BLOCK", f"Blocked request from {addr}: {data[:50]}")
            client_socket.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\nBlocked by firewall")
            break

        if addr[0] in BLOCKED_IPS:
            log("BLOCK", f"Blocked IP: {addr[0]}")
            client_socket.close()
            continue

        now = time.time()
        REQUESTS[addr[0]] = [t for t in REQUESTS[addr[0]] if now - t < WINDOW]

        if len(REQUESTS[addr[0]]) >= RATE_LIMIT:
            log("WARN", f"Rate limit exceeded: {addr[0]}")
            client_socket.close()
            return

        REQUESTS[addr[0]].append(now)


        remote.sendall(data)
        response = remote.recv(4096)

        client_socket.sendall(response)

    client_socket.close()
    if remote:
        remote.close()



def is_allowed(data):
    for word in BLOCKED_KEYWORDS:
        if word in data.lower():
            return False
    return True



start_firewall()