; Assemble this example with the Python utility 'assembler.py' 
; Found at https://github.com/johnnyw66/SAP2
; Eg. python3 assembler.py sqrt.asm

.org 0x8000

movi r0,197
movi r1,1
movi r2,1

:loop
; Display the current estimate of sqr(197)
out r2
sub r0,r1
jpv foundit
jpz foundit

:continue
addi r1,2
inc r2
jmp loop

:foundit
hlt

.end
