# Lab 2 — CVE, CVSS & CWE Correlation Lab (Manual Analysis)

---

## Objective

Train students to **understand findings, not blindly trust scanners.**
Manually correlate 3 vulnerabilities from Lab 1 with CVE, CVSS, and CWE data — then decide if each is exploitable in this environment.

> 💡 **Key Learning: CVSS ≠ Actual Business Risk**

---

## Step 1 — Choose 3 Findings from Lab 1

Three findings selected from the Metasploitable2 scan, each from a **different category**:

| # | Vulnerability | Category |
|---|---|---|
| 1 | Apache Tomcat SEoL (<= 5.5.x) | Web / Application |
| 2 | VNC Server 'password' Password | Service / Authentication |
| 3 | Canonical Ubuntu Linux SEoL (8.04.x) | OS / Platform |

---

## Finding 1 — Apache Tomcat SEoL (<= 5.5.x)

**Category:** Web / Application
**CVE:** CVE-2007-0450

> **Analyst Note:** SEoL (Supported End of Life) findings do not map to a single CVE. They indicate the software no longer receives security patches. The most critical known CVE for Apache Tomcat 5.5.x was selected for analysis.

---

### Step 2 — Open CVE Page on CVE.org, then Cross-Check on NVD

- **CVE.org:** https://www.cve.org/CVERecord?id=CVE-2007-0450
- **NVD:** https://nvd.nist.gov/vuln/detail/CVE-2007-0450

Both sources confirm the vulnerability exists in Apache Tomcat versions **5.5.0 through 5.5.21**.

---

### Step 3 — CVSS Vector String Breakdown

```
CVSS v2 Score : 5.0 (Medium)
Vector String : AV:N/AC:L/Au:N/C:P/I:N/A:N
```

| Metric | Value | Meaning |
|---|---|---|
| Attack Vector (AV) | `Network` | Exploitable remotely over the network |
| Attack Complexity (AC) | `Low` | No special conditions required |
| Privileges Required (Au) | `None` | No authentication required |
| User Interaction | `None` | No user action needed |
| Confidentiality Impact | `Partial` | Can read sensitive files |
| Integrity Impact | `None` | No modification possible |
| Availability Impact | `None` | No disruption possible |

---

### Step 4 — CWE Mapping

| Field | Value |
|---|---|
| CWE ID | **CWE-22** |
| CWE Name | Improper Limitation of a Pathname to a Restricted Directory (Path Traversal) |
| Source | NVD lists CWE-22 for CVE-2007-0450 |
| Description | Attacker uses `../` sequences in URL to escape the web root and read files outside the intended directory |

---

### Step 5 — Compare Against Lab Environment

| Question | Answer | Notes |
|---|---|---|
| Is the vulnerable service running? | ✅ YES | Apache Tomcat 5.5.x active |
| Is the port reachable from Kali? | ✅ YES | Port 8180 open |
| Does it require auth you don't have? | ❌ NO | No authentication needed |

---

### Step 6 — Conclusion

> ✅ **Verdict: LIKELY EXPLOITABLE**

Apache Tomcat 5.5.x is running on **port 8180** and is reachable from Kali Linux. CVE-2007-0450 allows an attacker to craft a URL with `../` path traversal sequences to read sensitive files outside the web root — no authentication required. Since the software is **SEoL (End of Life)**, this vulnerability will **never be patched** on this system. Although the CVSS score is 5.0 Medium (partial confidentiality impact only), in a real environment file disclosure can lead to further compromise — for example, reading configuration files that contain credentials.

---

## Finding 2 — VNC Server 'password' Password

**Category:** Service / Authentication
**CVE:** CVE-1999-0506

> **Analyst Note:** This is a credential/configuration finding rather than a code vulnerability. CVE-1999-0506 covers machines with weak or easily guessable passwords on remote access services such as VNC.

---

### Step 2 — Open CVE Page on CVE.org, then Cross-Check on NVD

- **CVE.org:** https://www.cve.org/CVERecord?id=CVE-1999-0506
- **NVD:** https://nvd.nist.gov/vuln/detail/CVE-1999-0506

Both sources confirm this as a **weak authentication** issue — the service uses a trivially guessable credential.

---

### Step 3 — CVSS Vector String Breakdown

```
CVSS v2 Score : 10.0 (Critical)
Vector String : AV:N/AC:L/Au:N/C:C/I:C/A:C
```

| Metric | Value | Meaning |
|---|---|---|
| Attack Vector (AV) | `Network` | Exploitable directly over the network |
| Attack Complexity (AC) | `Low` | Trivial — password is literally `password` |
| Privileges Required (Au) | `None` | No prior account or access needed |
| User Interaction | `None` | No user action needed |
| Confidentiality Impact | `Complete` | Full system access obtained |
| Integrity Impact | `Complete` | Attacker can modify anything |
| Availability Impact | `Complete` | Can disrupt or crash the system |

---

### Step 4 — CWE Mapping

| Field | Value |
|---|---|
| CWE ID | **CWE-521** |
| CWE Name | Weak Password Requirements |
| Source | NVD lists CWE-521 for weak credential vulnerabilities |
| Description | The system does not enforce strong password requirements, allowing trivially guessable credentials like `password` to be used on a remote access service |

---

### Step 5 — Compare Against Lab Environment

| Question | Answer | Notes |
|---|---|---|
| Is the vulnerable service running? | ✅ YES | VNC active on Metasploitable2 |
| Is the port reachable from Kali? | ✅ YES | Port 5900 open |
| Does it require auth you don't have? | ❌ NO | Password is `password` |

---

### Step 6 — Conclusion

> 🔴 **Verdict: LIKELY EXPLOITABLE — Highest Immediate Priority**

VNC is running on **port 5900** and directly reachable from Kali Linux. The password is set to `password` — trivially guessable. An attacker needs only a VNC client (e.g., `vncviewer <target-ip>`) and this credential to gain **full graphical desktop control** of the target — no exploit code required. This is the most immediately dangerous finding in the lab environment. While other vulnerabilities have complex exploit chains, this one requires **zero skill** to execute. The CVSS score of 10.0 Critical accurately reflects the real-world risk in this environment.

---

## Finding 3 — Canonical Ubuntu Linux SEoL (8.04.x)

**Category:** OS / Platform
**CVE:** CVE-2009-1185

> **Analyst Note:** Ubuntu 8.04 LTS reached End of Life in **May 2013** and no longer receives kernel or OS patches. CVE-2009-1185 was selected as a high-impact privilege escalation vulnerability known to affect kernel 2.6.24 running on this system.

---

### Step 2 — Open CVE Page on CVE.org, then Cross-Check on NVD

- **CVE.org:** https://www.cve.org/CVERecord?id=CVE-2009-1185
- **NVD:** https://nvd.nist.gov/vuln/detail/CVE-2009-1185

Both sources confirm the flaw in **udev** Netlink message handling on Linux kernel 2.6.24 — the exact version running on Metasploitable2.

---

### Step 3 — CVSS Vector String Breakdown

```
CVSS v2 Score : 7.2 (High)
Vector String : AV:L/AC:L/Au:N/C:C/I:C/A:C
```

| Metric | Value | Meaning |
|---|---|---|
| Attack Vector (AV) | `Local` | Attacker must already have local access to the system |
| Attack Complexity (AC) | `Low` | No special conditions required once local access is obtained |
| Privileges Required (Au) | `None` | No elevated privileges needed to trigger the exploit |
| User Interaction | `None` | No user action needed |
| Confidentiality Impact | `Complete` | Full root access achieved |
| Integrity Impact | `Complete` | Full control over system files |
| Availability Impact | `Complete` | Can crash or disrupt the system |

---

### Step 4 — CWE Mapping

| Field | Value |
|---|---|
| CWE ID | **CWE-264** |
| CWE Name | Permissions, Privileges and Access Controls |
| Source | NVD lists CWE-264 for CVE-2009-1185 |
| Description | A flaw in the udev Netlink message handling allows a local attacker to send crafted messages and gain root privileges through improper privilege enforcement in the kernel |

---

### Step 5 — Compare Against Lab Environment

| Question | Answer | Notes |
|---|---|---|
| Is the vulnerable service running? | ✅ YES | udev runs on Ubuntu 8.04 |
| Is the port reachable from Kali? | ⚠️ LOCAL ONLY | Requires prior foothold on target |
| Does it require auth you don't have? | ❌ NO | Any local user can trigger the exploit |

---

### Step 6 — Conclusion

> 🟠 **Verdict: LIKELY EXPLOITABLE (Second-Stage / Post-Foothold)**

Ubuntu 8.04 running kernel 2.6.24 is directly affected by CVE-2009-1185. The attack vector is **Local** — this exploit **cannot** be triggered directly from Kali. The attacker must first gain a shell on the target through another vulnerability (e.g., the VNC finding above). Once a low-privilege shell is obtained, this udev privilege escalation can be used to gain **full root access**. Since the OS is SEoL, this will never be patched.

> ⚠️ **Analyst Observation:** The CVSS score is 7.2 (High), yet this is a **second-stage exploit** — it requires a prior foothold. This demonstrates that CVSS scores must always be interpreted alongside the **Attack Vector** and **environmental context**, not taken at face value.

---

## Key Learning — CVSS ≠ Actual Business Risk

> *"CVSS score reflects abstract, generalised conditions. A real analyst must evaluate context — environment, exposure, and exploitability — not just the number."*

| Finding | CVSS | Reality in This Environment |
|---|---|---|
| Apache Tomcat (CVE-2007-0450) | 5.0 Medium | Permanently unpatched (SEoL) — real risk is higher than score implies |
| VNC 'password' (CVE-1999-0506) | 10.0 Critical | Score is accurate — instantly exploitable, zero skill required |
| Ubuntu SEoL (CVE-2009-1185) | 7.2 High | Requires local access first — lower immediate threat despite high score |

A good vulnerability analyst always **validates findings contextually** — not blindly by score.
**Blind reporting = bad analyst.**

---

## Conclusion Summary

| # | CVE | CVSS Score | CWE | Service Running? | Port Reachable? | Auth Required? | Verdict |
|---|---|---|---|---|---|---|---|
| 1 | CVE-2007-0450 | 5.0 Medium | CWE-22 | ✅ Yes | ✅ Yes (8180) | ❌ None | Exploitable |
| 2 | CVE-1999-0506 | 10.0 Critical | CWE-521 | ✅ Yes | ✅ Yes (5900) | ❌ None | **Exploitable — Critical** |
| 3 | CVE-2009-1185 | 7.2 High | CWE-264 | ✅ Yes | ⚠️ Local Only | ❌ None | Exploitable (post-foothold) |
