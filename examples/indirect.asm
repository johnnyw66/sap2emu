.org 0x8400

movwi r0,text
:loop
; ld r2, [r0r1]
.db 0x4e 
and r2,r2
jpz finish
; Display the current estimate of sqr(197)
out r2
addi r1, 1
jpnc loop
addi r0, 1
jmp loop

:finish
hlt

:text
.dt 'Hello WorldA'

.end
