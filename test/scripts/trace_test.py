#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import unittest

from libdebug import debugger

class TraceTest(unittest.TestCase):
    def setUp(self):
        self.d = debugger("binaries/trace_test")

    def test_trace_basic(self):
        d = self.d
        d.run()
        bp = d.breakpoint(0x40114d)
        bbp = d.breakpoint(0x40114a)
        d.cont()
        d.trace() #@ 4d
        d.cont()
        self.assertTrue(d._internal_debugger.trace_counter == 22)
        d.cont()
        self.assertTrue(d._internal_debugger.trace_counter == 41)
        index=1
        while index < 10:
            if index==4:
                d.step()
                self.assertTrue(d._internal_debugger.trace_counter == 99)
            elif index==7:
                self.assertTrue(d._internal_debugger.trace_counter == 155)
                d.step_until(0x401136)
                self.assertTrue(d._internal_debugger.trace_counter == 167)
            elif index==9:
                self.assertTrue(d._internal_debugger.trace_counter == 193)
            d.cont()
            index+=1
        self.assertTrue(d._internal_debugger.trace_counter == 223)
        d.kill()


if __name__ == "__main__":
    unittest.main()
