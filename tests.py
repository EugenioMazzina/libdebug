from libdebug import debugger

d=debugger("test/binaries/trace_test")
d.run()
a=lambda t,b : print(hex(t.regs.rip))
bp = d.breakpoint(0x40114d)
bbbp = d.breakpoint(0x401136)
print(hex(d.regs.rip))
d.cont() #hit bp
print(hex(d.regs.rip)) #4d
d.trace()
d.cont() #hit bbp
#d.finish(heuristic="step-mode")
print(hex(d.regs.rip)) #3e
#d.trace()
d.cont() #hit bbbp
#d.finish(heuristic="step-mode")
#d.trace()
#print(hex(d.regs.rip)) #7c
index=1
while index < 10:
    if index == 9:
        bbp=d.breakpoint(0x401144)
    d.cont()
    index+=1
d.cont()
#d.step_until(0x401170)
print(hex(d.regs.rip))
d.trace()
d.kill()
