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

bits 16
cpu 8086
org 0x7c000


start:
  ; Point ES:BX to the offset of where we're going to jump to after reading a
  ; sector.
  mov   bx, cs
  mov   es, bx
  mov   bx, boot_code

  mov   ax, 0x0201        ; Subfunction 2, read 1 sector
  mov   cx, 0x0002        ; Cylinder 0, start read at sector 2
  mov   dx, 0x0000        ; Head 0, drive 0x00 (first hard disk)
  int   0x13

  ; On success, jump to the boot code.
  jnc   boot_code

  ; If we failed then hang
  mov   ax, 0xdead
  cli
  hlt

; Pad to the end of the sector and then add the boot signature
times 510-($-$$) db 0
db 0x55, 0xaa

; Start of the second sector
boot_code:
  mov   ax, 0x1234
  cli
  hlt

; Pad to the end of the sector
times 1024-($-$$) db 0
