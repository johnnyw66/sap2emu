; python3 assembler.py indirect.asm -r
.org 0
jmp start

.org 0x8400
:start
movwi r0,text
:loop
ld r2,(r0)
and r2,r2
jpz finish
out r2
addi r1, 1
jpnc loop
addi r0, 1
jmp loop

:finish
hlt

:text
.dt 'Hello World'

.end
