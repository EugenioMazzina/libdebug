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
        bp = d.breakpoint("base_test")
        bbp = d.breakpoint("base_test_2")
        d.cont()
        d.trace()
        d.cont()
        result = d.trace()
        self.assertTrue(result == 8)
        d.cont()
        result = d.trace()
        self.assertTrue(result == 12)
        d.kill()


if __name__ == "__main__":
    unittest.main()
