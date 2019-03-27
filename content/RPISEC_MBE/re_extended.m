### Extended Reverse Engineering
#### This lecture introduces us to the concept of ```Dynamic Analysis```. As compared to the first lesson where static analysis (examining the code) is done, dynamic analysis deals with evaluating and testing a program by executing it in real time. We'll be using the GNU debugger, or ```gdb``` for short, to dynamically analyze the binaries from the first lesson. 
### crackme0x00a
#### First thing we need to do is disassemble the main function of the binary - to see the inner workings of it. We start up gdb:
```
$ gdb ./crackme0x00a
  gdb-peda$ disas main
    Dump of assembler code for function main:
       0x080484e4 <+0>:	push   ebp
       0x080484e5 <+1>:	mov    ebp,esp
       0x080484e7 <+3>:	and    esp,0xfffffff0
       0x080484ea <+6>:	sub    esp,0x30
       0x080484ed <+9>:	mov    eax,gs:0x14
       0x080484f3 <+15>:	mov    DWORD PTR [esp+0x2c],eax
       0x080484f7 <+19>:	xor    eax,eax
       0x080484f9 <+21>:	mov    eax,0x8048640
       0x080484fe <+26>:	mov    DWORD PTR [esp],eax
       0x08048501 <+29>:	call   0x80483d0 <printf@plt>
       0x08048506 <+34>:	mov    eax,0x8048651
       0x0804850b <+39>:	lea    edx,[esp+0x13]
       0x0804850f <+43>:	mov    DWORD PTR [esp+0x4],edx
       0x08048513 <+47>:	mov    DWORD PTR [esp],eax
       0x08048516 <+50>:	call   0x8048420 <__isoc99_scanf@plt>
       0x0804851b <+55>:	lea    eax,[esp+0x13]
       0x0804851f <+59>:	mov    DWORD PTR [esp+0x4],eax
       0x08048523 <+63>:	mov    DWORD PTR [esp],0x804a024
       0x0804852a <+70>:	call   0x80483c0 <strcmp@plt>
       0x0804852f <+75>:	test   eax,eax
       0x08048531 <+77>:	jne    0x8048554 <main+112>
       0x08048533 <+79>:	mov    DWORD PTR [esp],0x8048654
       0x0804853a <+86>:	call   0x80483f0 <puts@plt>
       0x0804853f <+91>:	nop
       0x08048540 <+92>:	mov    eax,0x0
       0x08048545 <+97>:	mov    edx,DWORD PTR [esp+0x2c]
       0x08048549 <+101>:	xor    edx,DWORD PTR gs:0x14
       0x08048550 <+108>:	je     0x8048567 <main+131>
       0x08048552 <+110>:	jmp    0x8048562 <main+126>
       0x08048554 <+112>:	mov    DWORD PTR [esp],0x804865e
       0x0804855b <+119>:	call   0x80483f0 <puts@plt>
       0x08048560 <+124>:	jmp    0x80484f9 <main+21>
       0x08048562 <+126>:	call   0x80483e0 <__stack_chk_fail@plt>
       0x08048567 <+131>:	leave  
       0x08048568 <+132>:	ret    
    End of assembler dump.
 ```
 #### Looking at the assembly code, we see some similar function calls such as printf which just prints something into our standard input. What we should be interested in begins at address ```0x0804850b``` - we see an lea instruction which initializes a pointer to our buffer with a size of 0x13 then we see 2 mov instructions moving stuff into the stack, after which a scanf is called to get user input. Whatever we input, is loaded next into the eax register, which is eventually moved into ```[esp+0x4]```, the value at 0x0x804a024 is then moved into the stack, and gets compared using the ```strcmp``` function. So what we have to do now is set a breakpoint before the compare, run to the next instruction, and examine the stack values. 
 ```
gdb-peda$ break *0x0804852a
  Breakpoint 1 at 0x804852a
gdb-peda$ r
  Starting program: /home/venom/Desktop/RPISEC_MBE/challenges/re_basic/crackme0x00a 
  Enter password: l33t
  [...]
  [------------------------------------stack-------------------------------------]
    0000| 0xffffcee0 --> 0x804a024 ("g00dJ0B!")
    0004| 0xffffcee4 --> 0xffffcef3 ("l33t")
    0008| 0xffffcee8 --> 0x8049ff4 --> 0x8049f28 --> 0x1 
    0012| 0xffffceec --> 0x8048591 (<__libc_csu_init+33>:	lea    eax,[ebx-0xe0])
    0016| 0xffffcef0 --> 0x6c000000 ('')
    0020| 0xffffcef4 --> 0x743333 ('33t')
    0024| 0xffffcef8 --> 0xf7ffd000 --> 0x26f34 
    0028| 0xffffcefc --> 0xf7e076a5 (<__cxa_atexit+37>:	add    esp,0x1c)
  [------------------------------------------------------------------------------]
    Breakpoint 1, 0x0804852a in main ()
 ```
 #### When we hit the breakpoint, gdb-peda automatically shows us values that are on the stack. And having a look at it, the password that we entered is stored at ```[esp+0x4]``` as we can see there it is. And the password that it is being compared to, which is loaded from 0x804a024, is the string 'g00dJ0B!'. We can now input this password and proceed with the next task:
 ```
 $ ./crackme0x00a
  Enter password: g00dJ0B!
  Congrats!
```
