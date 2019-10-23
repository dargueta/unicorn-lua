bits 32
cpu 386
org 0x7c000


entry_point:
  mov   edi, 0xb8000
  mov   esi, message
  mov   ecx, [n_chars]
  cld

  ; AH is the text attribute. Start with red on a black background and increment
  ; it on every iteration to change the text color.
  mov   ah, 0x01
  .print_loop:
    lodsb
    stosw
    inc   ah
    loop  .print_loop

  .done:
    cli
    hlt

message: db "Hello, World!"
n_chars: dd ($ - message)

; Pad to the end of the sector and then add the boot signature.
times 510-($-$$) db 0
db  0x55, 0xaa
