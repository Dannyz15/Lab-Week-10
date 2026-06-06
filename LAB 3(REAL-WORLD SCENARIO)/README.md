# Lab 3 — False Positive Validation Exercise (Real-World Scenario)

## Objective

Force students to think like professionals who must **defend their findings**.
Manually validate each scanner finding and classify it as:

| Classification | Meaning |
|---|---|
| ✅ True Positive (TP) | Scanner is correct — vulnerability is real and confirmed |
| ❌ False Positive (FP) | Scanner is wrong — vulnerability does not actually exist |
| ⚠️ Accepted Risk (AR) | Vulnerability is real but organisation chooses not to remediate |

> 💡 **Key Learning: This is EXACTLY what real VA analysts do. Blind reporting = bad analyst.**

---

## Scanner Reports (3 Findings to Validate)

| # | Finding | Port | Category |
|---|---|---|---|
| 1 | SSL Weak Cipher | 443 | Crypto / SSL |
| 2 | Open Port with No Authentication | 23 | Service |
| 3 | Outdated Service | 21 | Service / Version |

---

## Finding 1 — SSL Weak Cipher

**Scanner Report:** SSL service is offering weak cipher suites (SSLv2 / RC4)
**Target Port:** 443 (HTTPS)

---

### Step 1 — Validate Manually

**Command 1 — Nmap SSL cipher enumeration:**

```bash
nmap --script ssl-enum-ciphers -p 443 192.168.56.106
```

**Actual Output:**

```
PORT      STATE    SERVICE
443/tcp   filtered https

Nmap done: 1 IP address (1 host up) scanned in 0.89 seconds
```

**Command 2 — Nmap service version scan:**

```bash
nmap -sV -p 443 192.168.56.106
```

**Actual Output:**

```
PORT      STATE    SERVICE  VERSION
443/tcp   filtered https

Service detection performed.
Nmap done: 1 IP address (1 host up) scanned in 1.32 seconds
```

**Command 3 — Netcat direct connection:**

```bash
nc -nv 192.168.56.106 443
```

**Actual Output:**

```
(UNKNOWN) [192.168.56.106] 443 (https) : Connection refused
```

---

### Step 2 — Confirm Weak Protocols/Ciphers Are Truly Offered

| Tool | Result | Conclusion |
|---|---|---|
| `nmap --script ssl-enum-ciphers` | `443/tcp filtered` — no cipher data returned | SSL service not reachable |
| `nmap -sV` | `443/tcp filtered` — no version detected | No service responding |
| `nc -nv` | `Connection refused` | No service listening on port 443 |

> 🔍 **Key Difference:**
> - `filtered` = firewall blocking the port, Nmap cannot determine state
> - `Connection refused` = **no service is listening at all** — most definitive result

All three tools agree — **port 443 has no active SSL/HTTPS service**.

---

### Step 3 — Decide: TP / FP / Accepted Risk

> ❌ **FALSE POSITIVE (FP)**

---

### Justify Decision (Technical Reasoning)

The scanner reported SSL Weak Cipher on port 443. Manual validation using three tools confirms:

- `nmap --script ssl-enum-ciphers` → port **filtered**, no cipher suite data returned
- `nmap -sV` → port **filtered**, no HTTPS version detected
- `nc -nv 192.168.56.106 443` → **Connection refused** — no service listening

The port is completely unreachable. No SSL handshake could be established, therefore no weak cipher could actually be exploited. The scanner likely flagged this based on the Apache version installed on the OS rather than confirming the SSL service was actively running and reachable.

**This finding should be marked as a False Positive and removed from the final vulnerability report.**

---

## Finding 2 — Open Port with No Authentication

**Scanner Report:** Port 23 (Telnet) is open and accepting connections without authentication
**Target Port:** 23 (Telnet)

---

### Step 1 — Validate Manually

**Command 1 — Nmap service version scan:**

```bash
nmap -sV -p 23 192.168.56.106
```

**Actual Output:**

```
PORT   STATE  SERVICE  VERSION
23/tcp open   telnet   Linux telnetd
```

**Command 2 — Netcat basic access test:**

```bash
nc -nv 192.168.56.106 23
```

**Actual Output:**

```
(UNKNOWN) [192.168.56.106] 23 (telnet) open

metasploitable login:
```

---

### Step 2 — Check If Login Is Required

| Question | Answer |
|---|---|
| Is the port open and reachable from Kali? | ✅ YES — port 23 open |
| Does a service respond immediately? | ✅ YES — Linux telnetd |
| Is there any network-level restriction? | ❌ NO — connects instantly |
| Are credentials transmitted encrypted? | ❌ NO — plaintext only |
| Are default credentials accepted? | ✅ YES — `msfadmin:msfadmin` |

---

### Step 3 — Decide: TP / FP / Accepted Risk

> ✅ **TRUE POSITIVE (TP)**

---

### Justify Decision (Technical Reasoning)

Port 23 is open and reachable from Kali Linux. Nmap confirms `Linux telnetd` is running. Netcat connects immediately and presents a login prompt with no network restrictions. Telnet transmits **all data in cleartext** — including usernames and passwords — making it trivially sniffable by any attacker on the same network:

```bash
# Any attacker on the network can capture credentials passively
tcpdump -i eth0 port 23 -A
# Username and password appear in plaintext in the capture
```

Additionally, Metasploitable2 uses default credentials (`msfadmin:msfadmin`) with no account lockout policy. The scanner finding is **accurate and manually confirmed**.

**Recommended Fix:** Disable Telnet immediately. Replace with SSH (port 22) which provides encrypted authentication and session traffic.

---

## Finding 3 — Outdated Service

**Scanner Report:** vsftpd 2.3.4 detected — outdated version with a known backdoor
**Target Port:** 21 (FTP)

---

### Step 1 — Validate Manually

**Command 1 — Banner grab with Netcat:**

```bash
nc -nv 192.168.56.106 21
```

**Actual Output:**

```
(UNKNOWN) [192.168.56.106] 21 (ftp) open
220 (vsFTPd 2.3.4)
```

**Command 2 — Banner grab with cURL:**

```bash
curl -I ftp://192.168.56.106
```

**Actual Output:**

```
220 (vsFTPd 2.3.4)
```

---

### Step 2 — Compare Version to Vendor Advisory / NVD

**NVD Search:** https://nvd.nist.gov/vuln/search?query=vsftpd+2.3.4

| Field | Value |
|---|---|
| CVE | CVE-2011-2523 |
| CVSS Score | 10.0 Critical |
| Affected Version | vsftpd 2.3.4 exactly |
| Vulnerability | Backdoor — appending `:)` to any username opens root shell on port 6200 |

**Version comparison:**

| Source | Reported Version | Match? |
|---|---|---|
| Scanner report | vsftpd 2.3.4 | — |
| `nc -nv` banner grab | vsftpd 2.3.4 | ✅ Confirmed |
| `curl -I` banner grab | vsftpd 2.3.4 | ✅ Confirmed |
| NVD CVE-2011-2523 | vsftpd 2.3.4 | ✅ Confirmed |

---

### Step 3 — Decide: TP / FP / Accepted Risk

> ✅ **TRUE POSITIVE (TP)**

---

### Justify Decision (Technical Reasoning)

Two independent banner grabs (`nc` and `curl`) confirm the service is running **vsftpd 2.3.4** — exactly matching the scanner report. NVD confirms **CVE-2011-2523 (CVSS 10.0 Critical)** for this exact version. The vulnerability is a deliberately planted backdoor:

```bash
# Step 1 — Trigger the backdoor
telnet 192.168.56.106 21
USER backdoor:)
PASS anything

# Step 2 — Connect to the opened root shell
nc 192.168.56.106 6200
# Result: instant root shell — full system compromise
```

No authentication is required. The backdoor is embedded in the binary itself — not a configuration issue. Since Metasploitable2 is SEoL, this will never be patched. The scanner finding is **accurate and manually confirmed**.

**Recommended Fix:** Immediately remove vsftpd 2.3.4. Replace with vsftpd 3.0.x or later. Disable FTP entirely if not required.

---

## Key Learning — This is EXACTLY What Real VA Analysts Do

> *"Blind reporting = bad analyst."*

| Finding | What Scanner Said | What Manual Validation Found | Verdict |
|---|---|---|---|
| SSL Weak Cipher | Weak ciphers on port 443 | Port 443 filtered + connection refused — no service running | ❌ False Positive |
| Open Port No Auth | Telnet open, no auth | Port 23 open, plaintext, default creds confirmed | ✅ True Positive |
| Outdated Service | vsftpd 2.3.4 detected | Banner grab confirms version + CVE-2011-2523 on NVD | ✅ True Positive |

### Why Finding 1 is the Most Valuable Result

Most students submit all 3 findings as True Positives without validating. Finding 1 is a **False Positive** — the scanner flagged a potential SSL weakness based on the installed Apache version, but manual validation with 3 tools (`nmap --script`, `nmap -sV`, `nc -nv`) proves the service is not running. **Submitting this without validation would be incorrect reporting.**

This is the exact skill Lab 3 is testing.

---

## Conclusion Summary

| # | Finding | Port | Tools Used | Validation Result | Verdict |
|---|---|---|---|---|---|
| 1 | SSL Weak Cipher | 443 | `nmap --script ssl-enum-ciphers`, `nmap -sV`, `nc -nv` | Port filtered + connection refused — no SSL service | ❌ False Positive |
| 2 | Open Port No Auth | 23 | `nmap -sV`, `nc -nv` | Telnet open, plaintext, default creds work | ✅ True Positive |
| 3 | Outdated Service | 21 | `nc -nv`, `curl -I`, NVD | vsftpd 2.3.4 + CVE-2011-2523 confirmed | ✅ True Positive |
