; Copyright (C) 2017-2025 by Diego Argueta
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

; ============================================================================ ;
; Sample program: Read the current date and time from the CMOS                 ;
;                                                                              ;
; The following program is ONLY intended as a brief example and SHOULD NOT be  ;
; used in production code, as reading from the CMOS is more complicated than   ;
; this.                                                                        ;
;                                                                              ;
; For an explanation of how to read from the CMOS in the real world, visit:    ;
; https://wiki.osdev.org/CMOS                                                  ;
; ============================================================================ ;

bits 32
cpu 486
org 0

%macro read_register 2
  mov   al, %1
  out   0x70, al
  in    al, 0x71
  mov   [%2], al
%endmacro


read_register   0, seconds
read_register   2, minutes
read_register   4, hours
read_register   6, wday
read_register   7, day
read_register   8, month
read_register   9, year
read_register   0x32, century

; Century in AL
cmp   al, 0
jne   add_year_to_century

; Century is *not* present, assume we're in the 21st century.
mov   al, 20

add_year_to_century:
  ; Multiply century by 100, add the year, and save it.
  mov     dl, 100
  mul     dl
  movzx   dx, BYTE [year]
  add   ax, dx
  mov   [full_year], ax

done:
  cli
  hlt

; Pad with NOP up to address 128 so the clock info is at a constant address.
times 128-($-$$) db 0x00

seconds:    db 0
minutes:    db 0
hours:      db 0
wday:       db 0
day:        db 0
month:      db 0
year:       db 0
century:    db 0
full_year:  dw 0

; Pad up to address 256 for alignment purposes
times 256-($-$$) db 0
