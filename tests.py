from libdebug import debugger

d=debugger("test/binaries/basic_test")
d.run()
d.print_maps()
bp = d.breakpoint(0x401058)
bbp= d.breakpoint(0x4011ca)
d.trace()
print(hex(d.regs.rip))
#print(d.mem())
#d.step_until(0x4011CA)
d.cont()
print(hex(d.regs.rip))
d.cont()
print(hex(d.regs.rip))
d.cont()
d.cont()
d.cont()
d.cont()
d.cont()
d.cont()
d.cont()
d.cont()
d.cont()
d.cont()
d.cont()
d.cont()
d.cont()
d.cont()
d.cont()
d.cont()
d.kill()
