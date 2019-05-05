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
