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
RATE_LIMIT = rules["rate_limit"]


parser = argparse.ArgumentParser()

parser.add_argument("--block-ip", help="Block an IP address")
parser.add_argument("--block-word", help="Block a keyword")
parser.add_argument("--rate-limit", type=int, help="Set new rate limit")

args = parser.parse_args()

if args.block_ip:
    BLOCKED_IPS.add(args.block_ip)

if args.block_word:
    BLOCKED_KEYWORDS.append(args.block_word.encode())

if args.rate_limit:
    RATE_LIMIT = args.rate_limit



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
    remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    remote.connect((TARGET_HOST, TARGET_PORT))


    while True:
        data = client_socket.recv(4096)
        if not data:
            break

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

        print("Request:")
        print(data.decode(errors="ignore"))

        remote.sendall(data)
        response = remote.recv(4096)

        client_socket.sendall(response)

    client_socket.close()
    remote.close()




def is_allowed(data):
    for word in BLOCKED_KEYWORDS:
        if word in data.lower():
            return False
    return True



start_firewall()