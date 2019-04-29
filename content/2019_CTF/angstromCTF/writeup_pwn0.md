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
```
