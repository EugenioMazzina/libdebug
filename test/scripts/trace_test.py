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
        bbp = d.breakpoint(0x40114a, hardware=True)
        d.cont()
        d.trace() #@ 4d
        d.cont()
        self.assertTrue(d._internal_debugger.trace_counter == 22)
        d.cont()
        self.assertTrue(d._internal_debugger.trace_counter == 41)
        index=0
        while index <9:
            d.cont()
            index+=1
        self.assertTrue(d._internal_debugger.trace_counter == 221)
        d.kill()


if __name__ == "__main__":
    unittest.main()
