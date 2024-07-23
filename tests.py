from libdebug import debugger
from pwn import process

r = process("test/binaries/attach_test")

d = debugger()
d.attach(r.pid)
bp = d.breakpoint("printName", hardware=True)
print(hex(d.regs.rsi))
#bpp=d.breakpoint(0x00101252, hardware=True)
d.cont()

r.recvuntil(b"name:")
r.sendline(b"Io_no")

d.cont()
d.kill()
