## HSCTF: A Byte
##### category: reverse engineering
> Just one byte makes all the difference.

#### Just a little sidenote: this CTF was held a few months ago, unfortunately I haven't had time to participate in it. Taking a try at these reversing challenges now to learn and improve my RE skills. First things first we are given a binary, and when we  run the `file` utility on it reveals the following information:
```
$ file a_byte
a_byte: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 3.2.0, BuildID[sha1]=88fe0ee8aed1a070d6555c7e9866e364a40f686c, stripped
```
#### Since this is a stripped binary, it'll take a bit of work debugging it. Loading the binary into gdb and disassembled the .text section to look at the code:
```
gdb-peda$ info files
[...]
0x0000000000000630 - 0x0000000000000922 is .text

gdb-peda$ pdisas 0x0000000000000630,0x0000000000000922
```
#### Running this command will give us lots of lines worth of assembly code, but I'll only be focusing on the chunks worth taking a note on.
```asm
   0x0000000000000742:	mov    DWORD PTR [rbp-0x44],edi
   0x0000000000000745:	mov    QWORD PTR [rbp-0x50],rsi
   0x0000000000000749:	mov    rax,QWORD PTR fs:0x28
   0x0000000000000752:	mov    QWORD PTR [rbp-0x8],rax
   0x0000000000000756:	xor    eax,eax
   0x0000000000000758:	cmp    DWORD PTR [rbp-0x44],0x2
   [...]
   0x000000000000077b:	mov    rax,QWORD PTR [rbp-0x50]
   0x000000000000077f:	mov    rax,QWORD PTR [rax+0x8]
   0x0000000000000783:	mov    QWORD PTR [rbp-0x38],rax
   0x0000000000000787:	mov    rax,QWORD PTR [rbp-0x38]
   0x000000000000078b:	mov    rdi,rax
   0x000000000000078e:	call   0x5f0 <strlen@plt>
   0x0000000000000793:	mov    DWORD PTR [rbp-0x3c],eax
   0x0000000000000796:	cmp    DWORD PTR [rbp-0x3c],0x23
```
#### We see that the content of `rbp-0x44` is checked if it is equal to 0x2. What this is is the number of arguments which needs to be passed as a command line argument in order for the binary to run. After which, it gets moved to serve as an argument to the strlen function and is checked if it's length is equal to 0x23 (35). 
```asm
   0x000000000000079c:	mov    DWORD PTR [rbp-0x40],0x0
   0x00000000000007a3:	jmp    0x7cd
   0x00000000000007a5:	mov    eax,DWORD PTR [rbp-0x40]
   0x00000000000007a8:	movsxd rdx,eax
   0x00000000000007ab:	mov    rax,QWORD PTR [rbp-0x38]
   0x00000000000007af:	add    rax,rdx
   0x00000000000007b2:	movzx  ecx,BYTE PTR [rax]
   0x00000000000007b5:	mov    eax,DWORD PTR [rbp-0x40]
   0x00000000000007b8:	movsxd rdx,eax
   0x00000000000007bb:	mov    rax,QWORD PTR [rbp-0x38]
   0x00000000000007bf:	add    rax,rdx
   0x00000000000007c2:	xor    ecx,0x1
   0x00000000000007c5:	mov    edx,ecx
   0x00000000000007c7:	mov    BYTE PTR [rax],dl
   0x00000000000007c9:	add    DWORD PTR [rbp-0x40],0x1
   0x00000000000007cd:	mov    eax,DWORD PTR [rbp-0x40]
   0x00000000000007d0:	cmp    eax,DWORD PTR [rbp-0x3c]
   0x00000000000007d3:	jl     0x7a5
   0x00000000000007d5:	mov    BYTE PTR [rbp-0x30],0x69
   0x00000000000007d9:	mov    BYTE PTR [rbp-0x2f],0x72
   0x00000000000007dd:	mov    BYTE PTR [rbp-0x2e],0x62
   0x00000000000007e1:	mov    BYTE PTR [rbp-0x2d],0x75
   0x00000000000007e5:	mov    BYTE PTR [rbp-0x2c],0x67
   0x00000000000007e9:	mov    BYTE PTR [rbp-0x2b],0x7a
   0x00000000000007ed:	mov    BYTE PTR [rbp-0x2a],0x76
   0x00000000000007f1:	mov    BYTE PTR [rbp-0x29],0x31
   0x00000000000007f5:	mov    BYTE PTR [rbp-0x28],0x76
   0x00000000000007f9:	mov    BYTE PTR [rbp-0x27],0x5e
   0x00000000000007fd:	mov    BYTE PTR [rbp-0x26],0x78
   0x0000000000000801:	mov    BYTE PTR [rbp-0x25],0x31
   0x0000000000000805:	mov    BYTE PTR [rbp-0x24],0x74
   0x0000000000000809:	mov    BYTE PTR [rbp-0x23],0x5e
   0x000000000000080d:	mov    BYTE PTR [rbp-0x22],0x6a
   0x0000000000000811:	mov    BYTE PTR [rbp-0x21],0x6f
   0x0000000000000815:	mov    BYTE PTR [rbp-0x20],0x31
   0x0000000000000819:	mov    BYTE PTR [rbp-0x1f],0x76
   0x000000000000081d:	mov    BYTE PTR [rbp-0x1e],0x5e
   0x0000000000000821:	mov    BYTE PTR [rbp-0x1d],0x65
   0x0000000000000825:	mov    BYTE PTR [rbp-0x1c],0x35
   0x0000000000000829:	mov    BYTE PTR [rbp-0x1b],0x5e
   0x000000000000082d:	mov    BYTE PTR [rbp-0x1a],0x76
   0x0000000000000831:	mov    BYTE PTR [rbp-0x19],0x40
   0x0000000000000835:	mov    BYTE PTR [rbp-0x18],0x32
   0x0000000000000839:	mov    BYTE PTR [rbp-0x17],0x5e
   0x000000000000083d:	mov    BYTE PTR [rbp-0x16],0x39
   0x0000000000000841:	mov    BYTE PTR [rbp-0x15],0x69
   0x0000000000000845:	mov    BYTE PTR [rbp-0x14],0x33
   0x0000000000000849:	mov    BYTE PTR [rbp-0x13],0x63
   0x000000000000084d:	mov    BYTE PTR [rbp-0x12],0x40
   0x0000000000000851:	mov    BYTE PTR [rbp-0x11],0x31
   0x0000000000000855:	mov    BYTE PTR [rbp-0x10],0x33
   0x0000000000000859:	mov    BYTE PTR [rbp-0xf],0x38
   0x000000000000085d:	mov    BYTE PTR [rbp-0xe],0x7c
   0x0000000000000861:	mov    BYTE PTR [rbp-0xd],0x0
   0x0000000000000865:	mov    rdx,QWORD PTR [rbp-0x38]
   0x0000000000000869:	lea    rax,[rbp-0x30]
   0x000000000000086d:	mov    rsi,rdx
   0x0000000000000870:	mov    rdi,rax
   0x0000000000000873:	call   0x610 <strcmp@plt>
```
#### Scrolling further down, we see that the buffer that we provide as the argument for the binary is run in a for loop wherein every character is XOR'ed with `0x1` which is then compared if it is equal to the long string stored at `rbp-0x30`. Given that XOR is reversible, what we can do is to take note of all of these characters loaded into rbp, XOR them with 1 and see the result. For this I created a short script:
##### rev.py
```python
#: Stack content
stack = [0x69, 0x72, 0x62, 0x75, 0x67, 0x7a, 0x76, 0x31, 0x76, 0x5e, 0x78, 0x31, 0x74, 0x5e, 0x6a, 0x6f, 0x31, 0x76, 0x5e, 0x76, 0x40, 0x32, 0x5e, 0x39, 0x69, 0x33, 0x63, 0x40, 0x31, 0x33, 0x38, 0x7c, 0]
print(''.join(chr(offset ^ 1) for offset in stack))
```
#### Running the script outputs the flag for us. Easy.
```
$ python rev.py
hsctf{w0w_y0u_kn0w_wA3_8h2bA029
```
