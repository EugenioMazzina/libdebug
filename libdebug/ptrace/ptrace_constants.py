#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from enum import IntEnum

PTRACE_EVENT_FORK       = 1
PTRACE_EVENT_VFORK      = 2
PTRACE_EVENT_CLONE      = 3
PTRACE_EVENT_EXEC       = 4
PTRACE_EVENT_VFORK_DONE = 5
PTRACE_EVENT_EXIT       = 6
PTRACE_EVENT_SECCOMP    = 7

SIGTRAP                 = 5
SYSCALL_SIGTRAP         = 0x80 | SIGTRAP


class StopEvents(IntEnum):
    """An enumeration of the stop events that ptrace can return."""
    CLONE_EVENT = (SIGTRAP | (PTRACE_EVENT_CLONE << 8))
    EXEC_EVENT = (SIGTRAP | (PTRACE_EVENT_EXEC << 8))
    EXIT_EVENT = (SIGTRAP | (PTRACE_EVENT_EXIT << 8))
    FORK_EVENT = (SIGTRAP | (PTRACE_EVENT_FORK << 8))
    VFORK_EVENT = (SIGTRAP | (PTRACE_EVENT_VFORK << 8))
    VFORK_DONE_EVENT = (SIGTRAP | (PTRACE_EVENT_VFORK_DONE << 8))
    SECCOMP_EVENT = (SIGTRAP | (PTRACE_EVENT_SECCOMP << 8))


class Commands(IntEnum):
    """An enumeration of the available ptrace commands."""
    PTRACE_TRACEME = 0
    PTRACE_PEEKTEXT = 1
    PTRACE_PEEKDATA = 2
    PTRACE_PEEKUSER = 3
    PTRACE_POKETEXT = 4
    PTRACE_POKEDATA = 5
    PTRACE_POKEUSER = 6
    PTRACE_CONT = 7
    PTRACE_KILL = 8
    PTRACE_SINGLESTEP = 9
    PTRACE_GETREGS = 12
    PTRACE_SETREGS = 13
    PTRACE_GETFPREGS = 14
    PTRACE_SETFPREGS = 15
    PTRACE_ATTACH = 16
    PTRACE_DETACH = 17
    PTRACE_GETFPXREGS = 18
    PTRACE_SETFPXREGS = 19
    PTRACE_SYSCALL = 24
    PTRACE_SETOPTIONS = 0x4200
    PTRACE_GETEVENTMSG = 0x4201
    PTRACE_GETSIGINFO = 0x4202
    PTRACE_SETSIGINFO = 0x4203
    PTRACE_GETREGSET = 0x4204
    PTRACE_SETREGSET = 0x4205
    PTRACE_SEIZE = 0x4206
    PTRACE_INTERRUPT = 0x4207
    PTRACE_LISTEN = 0x4208
    PTRACE_PEEKSIGINFO = 0x4209
    PTRACE_GETSIGMASK = 0x420a
    PTRACE_SETSIGMASK = 0x420b
    PTRACE_SECCOMP_GET_FILTER = 0x420c
    PTRACE_SECCOMP_GET_METADATA = 0x420d
    PTRACE_GET_SYSCALL_INFO = 0x420e
