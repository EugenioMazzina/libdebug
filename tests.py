from libdebug import debugger

d=debugger("test/binaries/trace_test")
d.run()
a=lambda t,b : print(hex(t.regs.rip))
bp = d.breakpoint(0x40115a, hardware=True)
dp= d.breakpoint(0x401167, hardware=True)
bbp= d.breakpoint(0x401130, hardware=True)
bbbp = d.breakpoint(0x40114c,hardware=True)
print(hex(d.regs.rip))
d.cont() #hit bp
print(hex(d.regs.rip))
d.trace()
d.cont() #hit bbp
print(hex(d.regs.rip))
#d.trace()
d.cont() #hit bbbp
#d.trace()
print(hex(d.regs.rip))
d.kill()
