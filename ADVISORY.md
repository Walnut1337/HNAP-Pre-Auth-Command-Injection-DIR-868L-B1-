# Security Advisory — D-Link DIR-868L B1 HNAP Pre-auth Command Injection

| Field | Value |
|---|---|
| Title | Unauthenticated OS command injection via the HNAP `SOAPACTION` header in D-Link DIR-868L rev. B1 leads to root code execution |
| Affected vendor | D-Link |
| Affected product | DIR-868L, hardware revision B1 |
| Affected firmware | v2.01b05 (`DIR868LB1_FW201b05.bin`, build 2015-01-29) — other versions untested |
| Vulnerable component | `/htdocs/cgibin` — MD5 `64a37f67c57dc25b3678dbcc8554c10e`, SHA-256 `d09c8d79cbe2e896e78a82adfcc3fab15f804a8ee551524fe148223071392a55` |
| Vulnerable function | HNAP dispatcher `sub_1A57C` (file offset), sink at `0x1AA34`/`0x1AA40` |
| Weakness | CWE-78 (improper neutralization of special elements used in an OS command) |
| CVSS 3.1 | **9.8** `AV:N/AC:L/PR:N/PR:N/UI:N/S:U/C:H/I:H/A:H` → `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| Attack vector | Network, **pre-authentication**, no user interaction (single HTTP GET + header) |
| CVE | pending (VulDB submission filed 2026-09-28) |

## 1. Summary

The HNAP (Home Network Administration Protocol) interface of the DIR-868L B1
is implemented in the multi-call CGI binary `/htdocs/cgibin`. Its dispatcher
must allow exactly one pre-auth action — `GetDeviceSettings` — for the
setup wizard. The implementation decides this with an **unanchored
`strstr()` substring match** on the `SOAPACTION` HTTP header, so *any*
request whose header contains
`http://purenetworks.com/HNAP1/GetDeviceSettings` skips the entire
authentication block (the `HNAP_AUTH` HMAC verification is never invoked).

The same header then supplies the "action name" — the text after its last
`/` — which is concatenated, **without any filtering**, into a command
string passed to `system()`. The web server executes CGIs as root. Because
the injected command inherits the CGI's stdout, an attacker additionally
receives command output in the HTTP response by prefixing it with a CGI
header line, yielding a complete interactive pre-auth command channel with
read-back.

## 2. Affected entry points

| Interface | Endpoint | Notes |
|---|---|---|
| LAN web UI (port 80) | `GET/POST /HNAP1/` | main httpd, HNAP service enabled (default) |

The action is not restricted to `GetDeviceSettings`: the substring merely
has to appear somewhere in the header, e.g.

```http
SOAPACTION: "http://purenetworks.com/HNAP1/GetDeviceSettings/; <payload>;"
```

## 3. Impact

Unauthenticated remote code execution as **root** on the router, with an
output channel: arbitrary command execution, configuration read/modify
(NVRAM, credentials), persistence, and pivoting into the LAN. Combined with
WAN-side exposure of the web port this is a full remote takeover.

## 4. Verification summary

| Level | Result |
|---|---|
| Static (IDA) | substring auth gate `sub_1A57C+0xC8`; unfiltered action into `sprintf`/`system` at `+0x4C4` |
| Unicorn (real binary, emulated uClibc) | HMAC verify function **never called**; `system()` receives the attacker string verbatim |
| qemu-arm user-mode | strace: `execve("/bin/sh", ["sh","-c","sh /var/run/; touch …"])`; injected commands run as `uid=0`; timing oracle exact (10.018 s) |
| FirmAE full-system HTTP | 401 for unknown action (control), spoofed prefix sleeps 10.02 s / 5.02 s (dose-dependent); command output returned; `/proc/self/status` shows `Uid: 0` |

Details and raw outputs: [analysis/verification.md](analysis/verification.md).

## 5. Related vulnerabilities (not duplicates)

* [CVE-2015-2051](https://nvd.nist.gov/vuln/detail/CVE-2015-2051) — same defect class on the DIR-645/815/810L generation; D-Link's advisories do **not** list DIR-868L.
* CVE-2018-6530 family — UPnP `soap.cgi` command injection, a different endpoint/handler in the same binary.

## 6. Remediation

1. Replace the substring check with an exact/anchored comparison of the
   action name against a whitelist of pre-auth actions.
2. Never build shell command lines from request data; replace the
   `sprintf`+`system` pattern with direct `execve` of fixed paths.
3. Reject `SOAPACTION` values that fail a strict URI grammar check.

## 7. Disclosure timeline

| Date | Event |
|---|---|
| 2026-09-28 | VulDB submission filed (CVE requested); public advisory published |

## 8. Credit

Discovered and researched by **`Walnut1337`** (`walnut1337@163.com`), 2026-09.
