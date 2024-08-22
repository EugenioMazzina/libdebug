from libdebug import debugger

d=debugger("test/binaries/trace_test")
d.run()
#d.print_maps()
bp = d.breakpoint(0x1011b6, hardware=True)
bbp= d.breakpoint(0x10117a, hardware=True)
print(hex(d.regs.rip))
d.cont()
d.trace()
d.cont()
d.trace()
print(hex(d.regs.rip))
d.kill()
