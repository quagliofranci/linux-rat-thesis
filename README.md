# PRISM — Linux RAT for Purple Team Exercise

> **Tesi di Laurea Magistrale** — Università degli Studi di Salerno  
> Corso: Penetration Testing ed Ethical Hacking  
> Titolo: *Sviluppo e Analisi di un RAT per Ambienti Linux Enterprise nel contesto di un Purple Team Exercise*  
> Relatori: Prof. Vincenzo Carletti, Prof. Pasquale Foggia, Prof. Fortunato Lodari  

---

## ⚠️ Disclaimer

Questo software è sviluppato **esclusivamente a scopo didattico** nell'ambito di un progetto di tesi universitaria.  
L'utilizzo al di fuori dell'ambiente GNS3 controllato del laboratorio è **vietato**.  
Il repository è **privato** e ad accesso riservato.

---

## Struttura del progetto

```
rat/
├── src/
│   ├── c2/
│   │   ├── prism.c          # Implant ICMP reverse beacon (target)
│   │   ├── prism_client.c   # C2 listener (Kali)
│   │   ├── chacha20.h       # Cifratura ChaCha20 (RFC 7539)
│   │   ├── dns_client.c     # Implant DNS tunneling (canale alternativo)
│   │   ├── dns_server.py    # C2 server DNS
│   │   ├── shell.php        # Webshell per initial access
│   │   └── deploy_gen.sh    # Script deploy PRISM via webshell
│   └── persistence/
│       └── (script persistenza 4-layer)
```

---

## Moduli implementati

### 1. Implant PRISM (prism.c)
- **C2**: ICMP reverse beacon — implant inizia la comunicazione verso Kali
- **Cifratura**: ChaCha20 (RFC 7539) con nonce casuale per ogni pacchetto
- **Evasion stack**:
  - Process name spoofing → appare come `[kworker/0:0]`
  - `setuid(0)` per escalation permanente a root
  - Syscall dirette x86-64 (bypass auditd/glibc hooking)
  - Log tampering con syscall dirette (rimuove IP C2 da syslog/auth.log)
  - Jitter randomizzato (beacon ogni 3–7s)
- **Lockfile**: `/tmp/.prism.lock` — previene istanze duplicate
- **MITRE ATT&CK**: T1095, T1036.005, T1562.006

### 2. DNS Tunneling (dns_client.c)
- Encoding base32 con alfabeto custom
- Beaconing con jitter 30s ± 10s
- Process name spoofing `[kworker/0:0]`
- **MITRE ATT&CK**: T1071.004

### 3. Persistenza 4-layer
- Layer 1: cron job in `/etc/cron.d/` (mimicry nome sistema)
- Layer 2: systemd service con `Restart=always`
- Layer 3: SSH `authorized_keys` su utenti privilegiati
- Layer 4: PAM backdoor
- **MITRE ATT&CK**: T1053.003, T1543.002, T1098.004

### 4. Initial Access
- Webshell PHP su portale web vulnerabile
- Deploy PRISM via base64 inline (senza wget)
- **MITRE ATT&CK**: T1190, T1505.003

---

## Topologia GNS3

| Host | IP | Ruolo |
|------|----|-------|
| Kali | 192.168.122.x | Attacker / C2 |
| WebServer | 10.0.2.10 | Target primario (DMZ) |
| JumpServer | 10.0.60.10 | Target lateral movement |
| Wazuh | 10.0.99.14 | SIEM (blue team) |
| DC | 10.0.70.100 | Obiettivo finale |
| OPNsense | gateway | Firewall |
