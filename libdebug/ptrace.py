NULL = 0
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
PTRACE_O_TRACESYSGOOD        = 0x00000001
PTRACE_O_TRACEFORK        = 0x00000002
PTRACE_O_TRACEVFORK   = 0x00000004
PTRACE_O_TRACECLONE        = 0x00000008
PTRACE_O_TRACEEXEC        = 0x00000010
PTRACE_O_TRACEVFORKDONE = 0x00000020
PTRACE_O_TRACEEXIT        = 0x00000040
PTRACE_O_MASK                = 0x0000007f
PTRACE_EVENT_FORK        = 1
PTRACE_EVENT_VFORK        = 2
PTRACE_EVENT_CLONE        = 3
PTRACE_EVENT_EXEC        = 4
PTRACE_EVENT_VFORK_DONE = 5,
PTRACE_EVENT_EXIT        = 6

WNOHANG = 1

AMD64_REGS = ["r15", "r14", "r13", "r12", "rbp", "rbx", "r11", "r10", "r9", "r8", "rax", "rcx", "rdx", "rsi", "rdi", "orig_rax", "rip", "cs", "eflags", "rsp", "ss", "fs_base", "gs_base", "ds", "es", "fs", "gs"]
