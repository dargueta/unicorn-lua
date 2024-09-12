; Copyright (C) 2017-2024 by Diego Argueta
;
; This program is free software; you can redistribute it and/or modify
; it under the terms of the GNU General Public License as published by
; the Free Software Foundation; either version 2 of the License, or
; (at your option) any later version.
;
; This program is distributed in the hope that it will be useful,
; but WITHOUT ANY WARRANTY; without even the implied warranty of
; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
; GNU General Public License for more details.
;
; You should have received a copy of the GNU General Public License along
; with this program; if not, write to the Free Software Foundation, Inc.,
; 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

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
