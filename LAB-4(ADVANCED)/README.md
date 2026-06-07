# Lab 4 - Risk-Based Vulnerability Prioritisation (Advanced)

## Objective

**Teach risk, not severity.**
Given 5 real Nessus findings, rank them based on Exploitability, Impact, and Exposure then explain why CVSS score alone is not enough.

> 💡 A vulnerability scored 9.8 can be more dangerous than one scored 10.0 depending on context.

---

## The 5 Nessus Findings

| # | Vulnerability | Plugin ID | CVSS v3 | Port |
|---|---|---|---|---|
| A | VNC Server 'password' Password | #61708 | 10.0 Critical | 5900 |
| B | Canonical Ubuntu Linux SEoL (8.04.x) | #201352 | 10.0 Critical | 80 |
| C | Apache Tomcat SEoL (<= 5.5.x) | #171340 | 10.0 Critical | 8180 |
| D | Bind Shell Backdoor Detection | #51988 | 9.8 Critical | 1524 |
| E | SSL Version 2 and 3 Protocol Detection | #20007 | 9.8 Critical | - |

---

## Step 1 - Scoring Scale (1-5)

### Exploitability
| Score | Meaning |
|---|---|
| 5 | Zero skill - one command, no tools or knowledge needed |
| 4 | Easy - public exploit or Metasploit module available |
| 3 | Moderate - some conditions or skill required |
| 2 | Hard - complex setup or prerequisites needed |
| 1 | Very hard - multiple chained prerequisites |

### Impact
| Score | Meaning |
|---|---|
| 5 | Instant root shell / full system compromise |
| 4 | High privilege access or significant data exposure |
| 3 | Partial access / file disclosure |
| 2 | Limited - info disclosure only |
| 1 | Minimal - negligible real damage |

### Exposure
| Score | Meaning |
|---|---|
| 5 | Port open, no auth, directly reachable from Kali |
| 4 | Reachable from Kali with minor conditions |
| 3 | Network-facing but requires extra steps |
| 2 | Limited network reach |
| 1 | Local only - cannot reach directly from Kali |

---

## Step 2 - Score Each Vulnerability

---

### A - VNC Server 'password' Password
**Plugin:** #61708 | **CVSS v3:** 10.0 | **Port:** 5900/tcp
**Nessus Output:** `Nessus logged in using a password of "password"` - Exploited by Nessus: **true**

| Category | Score | Reasoning |
|---|---|---|
| Exploitability | **5** | Nessus logged in automatically. Run `vncviewer 192.168.56.106` and type `password` - zero skill required |
| Impact | **5** | Full graphical desktop access = complete system control |
| Exposure | **5** | Port 5900 open, network-facing, directly reachable from Kali, no firewall |
| **TOTAL** | **15 / 15** | |

---

### B - Canonical Ubuntu Linux SEoL (8.04.x)
**Plugin:** #201352 | **CVSS v3:** 10.0 | **Port:** 80/tcp
**Nessus Output:** `Security End of Life: May 9, 2013 - Time since SEoL: >= 13 years`

| Category | Score | Reasoning |
|---|---|---|
| Exploitability | **2** | SEoL is not a direct exploit - requires a specific CVE to trigger, often needs a prior foothold on the system |
| Impact | **5** | OS-level compromise = full root access if a kernel CVE is exploited |
| Exposure | **3** | Detected on port 80 but OS/kernel exploits typically require local access or a chained attack |
| **TOTAL** | **10 / 15** | |

---

### C - Apache Tomcat SEoL (<= 5.5.x)
**Plugin:** #171340 | **CVSS v3:** 10.0 | **Port:** 8180/tcp
**Nessus Output:** `Installed version: 5.5 - Security End of Life: September 30, 2012 - >= 13 years`

| Category | Score | Reasoning |
|---|---|---|
| Exploitability | **3** | SEoL means permanently unpatched. Multiple known CVEs exist for Tomcat 5.5.x but require crafted requests |
| Impact | **4** | Web server compromise - path traversal for file disclosure, possible RCE via known CVEs |
| Exposure | **4** | Port 8180 open, directly reachable from Kali, no authentication on manager app |
| **TOTAL** | **11 / 15** | |

---

### D - Bind Shell Backdoor Detection
**Plugin:** #51988 | **CVSS v3:** 9.8 | **Port:** 1524/tcp
**Nessus Output:**
```
Nessus was able to execute the command "id" using the following request:
root@metasploitable:/# uid=0(root) gid=0(root) groups=0(root)
```

| Category | Score | Reasoning |
|---|---|---|
| Exploitability | **5** | No tools, no exploit, no password needed. Just `nc 192.168.56.106 1524` - instant shell. Nessus confirmed this automatically |
| Impact | **5** | Already running as **root** (uid=0). Complete and immediate system compromise |
| Exposure | **5** | Port 1524 open, zero authentication, directly reachable from Kali |
| **TOTAL** | **15 / 15** | |

---

### E - SSL Version 2 and 3 Protocol Detection
**Plugin:** #20007 | **CVSS v3:** 9.8
**Nessus Description:** Remote service accepts SSL 2.0/3.0 - susceptible to MITM, POODLE, DROWN attacks

| Category | Score | Reasoning |
|---|---|---|
| Exploitability | **3** | Requires attacker to be in a MITM position on the network - not a one-click exploit, needs specific attack conditions |
| Impact | **3** | Can decrypt intercepted communications - no direct shell or system access granted |
| Exposure | **4** | Network-facing service reachable from Kali, but attacker must be on the same network segment |
| **TOTAL** | **10 / 15** | |

---

## Step 3 - Full Scoring Summary

| Rank | Vulnerability | CVSS v3 | Exploitability | Impact | Exposure | Risk Score |
|---|---|---|---|---|---|---|
| 🥇 1st | D - Bind Shell Backdoor | 9.8 | 5 | 5 | 5 | **15 / 15** |
| 🥈 2nd | A - VNC 'password' | 10.0 | 5 | 5 | 5 | **15 / 15** |
| 🥉 3rd | C - Apache Tomcat SEoL | 10.0 | 3 | 4 | 4 | **11 / 15** |
| 4th | B - Ubuntu SEoL | 10.0 | 2 | 5 | 3 | **10 / 15** |
| 5th | E - SSL v2/v3 Detection | 9.8 | 3 | 3 | 4 | **10 / 15** |

---

## Step 4 - Remediation Priority List

---

### 🔴 Priority 1 - Bind Shell Backdoor (Port 1524)

This is the single most dangerous finding in the scan. A root shell is sitting open on port 1524 with **zero authentication**. Nessus confirmed exploitation by running `id` and receiving `uid=0(root)`. Any attacker who connects with Netcat gets an immediate root shell - no password, no exploit code, no skill required:

```bash
nc 192.168.56.106 1524
# Instant root shell
```

The system should be treated as **already compromised**. Verify whether the backdoor was planted by a prior attack. Reinstall the system if necessary. This takes Priority 1 over VNC despite having a lower CVSS score (9.8 vs 10.0) because it requires absolutely nothing to exploit.

---

### 🔴 Priority 2 - VNC Server 'password' Password (Port 5900)

Nessus successfully logged into the VNC service automatically using the password `password`. Full graphical desktop access is available to any attacker on the network. Ranked 2nd because Bind Shell gives root access with even less friction. Fix immediately - either set a strong VNC password or disable the VNC service if not required.

```bash
# Any attacker on the network can run this
vncviewer 192.168.56.106
# Password: password
# Result: full desktop control
```

---

### 🟠 Priority 3 - Apache Tomcat SEoL <= 5.5.x (Port 8180)

Running version 5.5 which reached End of Life on September 30, 2012 - permanently unpatched for over 13 years. Multiple known CVEs exist for this version. Port 8180 is directly reachable from Kali with no authentication on the manager application. Upgrade to a currently supported Tomcat version immediately.

---

### 🟡 Priority 4 - Canonical Ubuntu Linux SEoL (8.04.x)

The entire OS has been unsupported since May 2013. Every kernel and OS vulnerability discovered after that date is permanently unpatched on this system. While not directly exploitable on its own, it acts as a multiplier - any new CVE targeting Ubuntu 8.04 will never be fixed. Fix: migrate to a currently supported Ubuntu LTS release.

---

### 🟢 Priority 5 - SSL Version 2 and 3 Protocol Detection

Real vulnerability but the lowest immediate priority in this environment. Exploiting SSL v2/v3 requires the attacker to be in a man-in-the-middle position, which is a higher-skill scenario compared to the other findings. No direct access or shell is gained. Fix: disable SSL 2.0 and 3.0 entirely. Configure the service to use TLS 1.2 or higher with strong cipher suites only.

---

## Step 5 - Why a Lower CVSS Can Outrank a Higher CVSS

> **Example: Bind Shell (CVSS 9.8) ranked #1 - VNC 'password' (CVSS 10.0) ranked #2**

| Factor | D - Bind Shell Backdoor (9.8) | A - VNC 'password' (10.0) |
|---|---|---|
| CVSS v3 Score | 9.8 ← lower on paper | 10.0 ← higher on paper |
| Exploitability | `nc 192.168.56.106 1524` - zero knowledge | `vncviewer` + type `password` |
| Authentication | **None at all** | Requires knowing the password (trivial) |
| Access Gained | **Instant root shell (uid=0)** | Full graphical desktop |
| Confirmed by Nessus? | ✅ `uid=0(root)` executed | ✅ logged in successfully |
| Risk Score | **15 / 15** | **15 / 15** |
| **Final Priority** | **#1** | **#2** |

> **Analyst Conclusion:**
> VNC scores 10.0 while Bind Shell scores 9.8 - but Bind Shell requires **literally nothing** to exploit. No password, no exploit code, just a raw TCP connection. A root shell with zero authentication is more immediately dangerous than a desktop that still requires a trivial credential. This proves that CVSS is a useful starting point but **exploitability and exposure in context** must always drive final prioritisation - not the raw score alone.

---

## Key Learning - Teach Risk, Not Severity

> *"CVSS measures theoretical severity. Risk is what actually matters in your environment."*

| Finding | CVSS | Looks Like | Reality |
|---|---|---|---|
| Bind Shell Backdoor | 9.8 | Lower score | 🔴 **#1 Priority** - root shell, zero auth, one command |
| VNC 'password' | 10.0 | Highest score | 🔴 **#2 Priority** - trivial but needs a password |
| Apache Tomcat SEoL | 10.0 | Highest score | 🟠 **#3 Priority** - unpatched but needs specific CVE |
| Ubuntu SEoL | 10.0 | Highest score | 🟡 **#4 Priority** - no direct exploit, needs chaining |
| SSL v2/v3 | 9.8 | Lower score | 🟢 **#5 Priority** - needs MITM, no direct access |

**Three vulnerabilities score 10.0 but rank #2, #3, and #4.
One vulnerability scores 9.8 but ranks #1.
CVSS alone would have gotten this completely wrong.**
