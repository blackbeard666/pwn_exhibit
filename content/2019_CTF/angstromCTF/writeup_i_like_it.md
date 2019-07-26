## angstromCTF: I Like It
##### category: Reverse Engineering
> Now I like dollars, I like diamonds, I like ints, I like strings. Make Cardi like it please.

#### These reversing challenges are part of angstromCTF which was held during the month of April. I'm taking a try at these now since I will be heavily focusing on learning android RE and malware analysis. First off we're given a 64-bit binary which seems to take user input. 
## Disassembly
#### We load the binary into gdb and analyze the main function. 
```
gdb-peda$ disas main 
Dump of assembler code for function main:
   0x00000000004007a6 <+0>:	push   rbp
   0x00000000004007a7 <+1>:   mov    rbp,rsp
   0x00000000004007aa <+4>:	sub    rsp,0x50
   0x00000000004007ae <+8>:	mov    DWORD PTR [rbp-0x44],edi
   0x00000000004007b1 <+11>:	mov    QWORD PTR [rbp-0x50],rsi
   0x00000000004007b5 <+15>:	mov    rax,QWORD PTR fs:0x28
   0x00000000004007be <+24>:	mov    QWORD PTR [rbp-0x8],rax
   0x00000000004007c2 <+28>:	xor    eax,eax
   0x00000000004007c4 <+30>:	mov    edi,0x400978
   0x00000000004007c9 <+35>:	call   0x400610 <puts@plt>
   0x00000000004007ce <+40>:	mov    rdx,QWORD PTR [rip+0x20089b]        # 0x601070 <stdin@@GLIBC_2.2.5>
   0x00000000004007d5 <+47>:	lea    rax,[rbp-0x20]
   0x00000000004007d9 <+51>:	mov    esi,0x14
   0x00000000004007de <+56>:	mov    rdi,rax
   0x00000000004007e1 <+59>:	call   0x400660 <fgets@plt>
   0x00000000004007e6 <+64>:	lea    rax,[rbp-0x20]
   0x00000000004007ea <+68>:	mov    rdi,rax
   0x00000000004007ed <+71>:	call   0x400620 <strlen@plt>
   0x00000000004007f2 <+76>:	sub    rax,0x1
   0x00000000004007f6 <+80>:	mov    BYTE PTR [rbp+rax*1-0x20],0x0
   0x00000000004007fb <+85>:	lea    rax,[rbp-0x20]
   0x00000000004007ff <+89>:	mov    esi,0x4009a1
   0x0000000000400804 <+94>:	mov    rdi,rax
   0x0000000000400807 <+97>:	call   0x400670 <strcmp@plt>
   0x000000000040080c <+102>:	test   eax,eax
   0x000000000040080e <+104>:	je     0x400824 <main+126>
   0x0000000000400810 <+106>:	mov    edi,0x4009ab
   0x0000000000400815 <+111>:	call   0x400610 <puts@plt>
   0x000000000040081a <+116>:	mov    edi,0x0
   0x000000000040081f <+121>:	call   0x400690 <exit@plt>
   0x0000000000400824 <+126>:	mov    edi,0x4009c2
   0x0000000000400829 <+131>:	call   0x400610 <puts@plt>
   0x000000000040082e <+136>:	mov    edi,0x4009e0
   0x0000000000400833 <+141>:	call   0x400610 <puts@plt>
   0x0000000000400838 <+146>:	mov    rdx,QWORD PTR [rip+0x200831]        # 0x601070 <stdin@@GLIBC_2.2.5>
   0x000000000040083f <+153>:	lea    rax,[rbp-0x30]
   0x0000000000400843 <+157>:	mov    esi,0xc
   0x0000000000400848 <+162>:	mov    rdi,rax
   0x000000000040084b <+165>:	call   0x400660 <fgets@plt>
   0x0000000000400850 <+170>:	lea    rcx,[rbp-0x34]
   0x0000000000400854 <+174>:	lea    rdx,[rbp-0x38]
   0x0000000000400858 <+178>:	lea    rax,[rbp-0x30]
   0x000000000040085c <+182>:	mov    esi,0x400a1d
   0x0000000000400861 <+187>:	mov    rdi,rax
   0x0000000000400864 <+190>:	mov    eax,0x0
   0x0000000000400869 <+195>:	call   0x400680 <__isoc99_sscanf@plt>
   0x000000000040086e <+200>:	mov    edx,DWORD PTR [rbp-0x38]
   0x0000000000400871 <+203>:	mov    eax,DWORD PTR [rbp-0x34]
   0x0000000000400874 <+206>:	add    eax,edx
   0x0000000000400876 <+208>:	cmp    eax,0x88
   0x000000000040087b <+213>:	jne    0x400897 <main+241>
   0x000000000040087d <+215>:	mov    edx,DWORD PTR [rbp-0x38]
   0x0000000000400880 <+218>:	mov    eax,DWORD PTR [rbp-0x34]
   0x0000000000400883 <+221>:	imul   eax,edx
   0x0000000000400886 <+224>:	cmp    eax,0xec7
   0x000000000040088b <+229>:	jne    0x400897 <main+241>
   0x000000000040088d <+231>:	mov    edx,DWORD PTR [rbp-0x38]
   0x0000000000400890 <+234>:	mov    eax,DWORD PTR [rbp-0x34]
   0x0000000000400893 <+237>:	cmp    edx,eax
   0x0000000000400895 <+239>:	jl     0x4008ab <main+261>
   0x0000000000400897 <+241>:	mov    edi,0x4009ab
   0x000000000040089c <+246>:	call   0x400610 <puts@plt>
   0x00000000004008a1 <+251>:	mov    edi,0x0
   0x00000000004008a6 <+256>:	call   0x400690 <exit@plt>
   0x00000000004008ab <+261>:	mov    edi,0x4009c2
   0x00000000004008b0 <+266>:	call   0x400610 <puts@plt>
   0x00000000004008b5 <+271>:	mov    ecx,DWORD PTR [rbp-0x34]
   0x00000000004008b8 <+274>:	mov    edx,DWORD PTR [rbp-0x38]
   0x00000000004008bb <+277>:	lea    rax,[rbp-0x20]
   0x00000000004008bf <+281>:	mov    rsi,rax
   0x00000000004008c2 <+284>:	mov    edi,0x400a23
   0x00000000004008c7 <+289>:	mov    eax,0x0
   0x00000000004008cc <+294>:	call   0x400640 <printf@plt>
   0x00000000004008d1 <+299>:	mov    eax,0x0
   0x00000000004008d6 <+304>:	mov    rcx,QWORD PTR [rbp-0x8]
   0x00000000004008da <+308>:	xor    rcx,QWORD PTR fs:0x28
   0x00000000004008e3 <+317>:	je     0x4008ea <main+324>
   0x00000000004008e5 <+319>:	call   0x400630 <__stack_chk_fail@plt>
   0x00000000004008ea <+324>:	leave  
   0x00000000004008eb <+325>:	ret    
End of assembler dump.
```
#### As we can see, after the first call to fgets, `strcmp` gets executed afterwards - comparing the user-supplied buffer stored at rax (which is moved to rdi) to a string from `0x4009a1` which is loaded into the edi register. Examining the value of the address reveals the string that is the answer of the first question.
```
gdb-peda$ x/s 0x4009a1
"okrrrrrrr"
```
#### Since we have provided the correct answer, the code flaw jumps to the address `400824` which then proceeds to get two space-separated integers, checks if their sum is equal to `0x88` and if multiplied results to `0xec7`. A final check is done to determine if the first number is less than the second one. To solve this, I created a short script to generate the numbers for us and send it to the challenge server.
##### rev.py
```python
from pwn import *

#: Connect to challenge server
binary = ELF('./i_like_it', checksec=False)
p = binary.process()
context.log_level = 'error'
print(p.recv())

#: Helper function
def cardi_numbers():

	multiply_res = 0xec7
	addition_res = 0x88

	for i in range(1, multiply_res // 2):
		factor1 = 0
		factor2 = 0

		if multiply_res % i == 0:
			factor1 = multiply_res // i
			factor2 = multiply_res // factor1

		if factor1 + factor2 == addition_res and factor1 < factor2:
			return(factor1, factor2)

cardi1, cardi2 = cardi_numbers()

#: Send payload
p.sendline('okrrrrrrr')
print(p.recv())
p.sendline('{} {}'.format(cardi1, cardi2))
print(p.recv())
```
#### Running the script gets us the flag composed of our answers.
```
$ python rev.py
I like the string that I'm thinking of: 

I said I like it like that!
I like two integers that I'm thinking of (space separated): 

I said I like it like that!
Flag: actf{okrrrrrrr_39_97}
```
