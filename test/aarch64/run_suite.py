#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import sys
import unittest

from scripts.basic_test import BasicTest


def fast_suite():
    suite = unittest.TestSuite()
    suite.addTest(BasicTest("test_registers"))
    return suite


def complete_suite():
    suite = fast_suite()
    return suite


def thread_stress_suite():
    suite = unittest.TestSuite()
    return suite


if __name__ == "__main__":
    if sys.version_info >= (3, 12):
        runner = unittest.TextTestRunner(verbosity=2, durations=3)
    else:
        runner = unittest.TextTestRunner(verbosity=2)

    if len(sys.argv) > 1 and sys.argv[1].lower() == "slow":
        suite = complete_suite()
    elif len(sys.argv) > 1 and sys.argv[1].lower() == "thread_stress":
        suite = thread_stress_suite()
        runner.verbosity = 1
    else:
        suite = fast_suite()

    result = runner.run(suite)

    if result.wasSuccessful():
        print("All tests passed")
    else:
        print("Some tests failed")
        print("\nFailed Tests:")
        for test, err in result.failures:
            print(f"{test}: {err}")
        print("\nErrors:")
        for test, err in result.errors:
            print(f"{test}: {err}")
