; Assemble this example with the Python utility 'assembler.py' 
; Found at https://github.com/johnnyw66/SAP2
; Eg. python3 assembler.py loop.asm

.org 0x8100

movi r0,197
:loop
; Display the current estimate of sqr(197)
out r0
djnz r0, loop

hlt

.end
