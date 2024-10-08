#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini, Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import io
import logging
import unittest

from libdebug import debugger


class AutoWaitingTest(unittest.TestCase):
    def setUp(self):
        # Redirect logging to a string buffer
        self.log_capture_string = io.StringIO()
        self.log_handler = logging.StreamHandler(self.log_capture_string)
        self.log_handler.setLevel(logging.WARNING)

        self.logger = logging.getLogger("libdebug")
        self.original_handlers = self.logger.handlers
        self.logger.handlers = []
        self.logger.addHandler(self.log_handler)
        self.logger.setLevel(logging.WARNING)

    def test_bps_auto_waiting(self):
        d = debugger("binaries/breakpoint_test", auto_interrupt_on_command=False)

        d.run()

        bp1 = d.breakpoint("random_function")
        bp2 = d.breakpoint(0x40115B)
        bp3 = d.breakpoint(0x40116D)

        counter = 1

        d.cont()

        while True:
            if d.regs.rip == bp1.address:
                self.assertTrue(bp1.hit_count == 1)
                self.assertTrue(bp1.hit_on(d))
                self.assertFalse(bp2.hit_on(d))
                self.assertFalse(bp3.hit_on(d))
            elif d.regs.rip == bp2.address:
                self.assertTrue(bp2.hit_count == counter)
                self.assertTrue(bp2.hit_on(d))
                self.assertFalse(bp1.hit_on(d))
                self.assertFalse(bp3.hit_on(d))
                counter += 1
            elif d.regs.rip == bp3.address:
                self.assertTrue(bp3.hit_count == 1)
                self.assertTrue(d.regs.rsi == 45)
                self.assertTrue(d.regs.esi == 45)
                self.assertTrue(d.regs.si == 45)
                self.assertTrue(d.regs.sil == 45)
                self.assertTrue(bp3.hit_on(d))
                self.assertFalse(bp1.hit_on(d))
                self.assertFalse(bp2.hit_on(d))
                break

            d.cont()

        d.kill()

    def test_jumpout_auto_waiting(self):
        flag = ""
        first = 0x55
        second = 0

        d = debugger("CTF/jumpout", auto_interrupt_on_command=False)

        r = d.run()

        bp1 = d.breakpoint(0x140B, hardware=True)
        bp2 = d.breakpoint(0x157C, hardware=True)

        d.cont()

        r.sendline(b"A" * 0x1D)

        while True:
            if d.regs.rip == bp1.address:
                second = d.regs.r9
            elif d.regs.rip == bp2.address:
                address = d.regs.r13 + d.regs.rbx
                third = int.from_bytes(d.memory[address, 1], "little")
                flag += chr((first ^ second ^ third ^ (bp2.hit_count - 1)))

            d.cont()

            if flag.endswith("}"):
                break

        r.recvuntil(b"Wrong...")

        d.kill()

        self.assertEqual(flag, "SECCON{jump_table_everywhere}")

class AutoWaitingNcuts(unittest.TestCase):
    def setUp(self):
        pass

    def get_passsphrase_from_class_1_binaries(self, previous_flag):
        flag = b""

        d = debugger("CTF/1", auto_interrupt_on_command=False)
        r = d.run()

        d.breakpoint(0x7EF1, hardware=True)

        d.cont()

        r.recvuntil(b"Passphrase:\n")
        r.send(previous_flag + b"a" * 8)

        for _ in range(8):
            offset = ord("a") ^ d.regs.rbp
            d.regs.rbp = d.regs.r13
            flag += (offset ^ d.regs.r13).to_bytes(1, "little")

            d.cont()

        r.recvline()

        d.kill()

        self.assertEqual(flag, b"\x00\x006\x00\x00\x00(\x00")
        return flag

    def get_passsphrase_from_class_2_binaries(self, previous_flag):
        bitmap = {}
        lastpos = 0
        flag = b""

        d = debugger("CTF/2", auto_interrupt_on_command=False)
        r = d.run()

        bp1 = d.breakpoint(0xD8C1, hardware=True)
        bp2 = d.breakpoint(0x1858, hardware=True)
        bp3 = d.breakpoint(0xDBA1, hardware=True)

        d.cont()

        r.recvuntil(b"Passphrase:\n")
        r.send(previous_flag + b"a" * 8)

        while True:
            if d.regs.rip == bp1.address:
                lastpos = d.regs.rbp
                d.regs.rbp = d.regs.r13 + 1
            elif d.regs.rip == bp2.address:
                bitmap[d.regs.r12 & 0xFF] = lastpos & 0xFF
            elif d.regs.rip == bp3.address:
                d.regs.rbp = d.regs.r13
                wanted = d.regs.rbp
                needed = 0
                for i in range(8):
                    if wanted & (2**i):
                        needed |= bitmap[2**i]
                flag += chr(needed).encode()

                if bp3.hit_count == 8:
                    d.cont()
                    break

            d.cont()

        d.kill()

        self.assertEqual(flag, b"\x00\x00\x00\x01\x00\x00a\x00")

    def get_passsphrase_from_class_3_binaries(self):
        flag = b""

        d = debugger("CTF/0", auto_interrupt_on_command=False)
        r = d.run()

        d.breakpoint(0x91A1, hardware=True)

        d.cont()

        r.send(b"a" * 8)

        for _ in range(8):
            offset = ord("a") - d.regs.rbp
            d.regs.rbp = d.regs.r13

            flag += chr((d.regs.r13 + offset) % 256).encode("latin-1")

            d.cont()

        r.recvline()

        d.kill()

        self.assertEqual(flag, b"BM8\xd3\x02\x00\x00\x00")
        return flag

    def test_ncuts(self):
        flag = self.get_passsphrase_from_class_3_binaries()
        flag = self.get_passsphrase_from_class_1_binaries(flag)
        self.get_passsphrase_from_class_2_binaries(flag)
