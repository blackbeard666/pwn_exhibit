## AngstromCTF: Chain of Rope
##### *tl;dr: chaining rop gadgets*
#### Guessing from the challenge title itself, this challenge will be solved by chaining together rop gadgets found inside the binary to get the flag. For the exploit, it can be done the hard way or the much easier way. I'll discuss the hard way first to have an understading on how to perform a simple rop chain on a 64-bit binary. 
#### Since we have the source code, first thing to do is to examine it:
```c
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int userToken = 0;
int balance = 0;

int authorize () {
	userToken = 0x1337;
	return 0;
}

int addBalance (int pin) {
	if (userToken == 0x1337 && pin == 0xdeadbeef) {
		balance = 0x4242;
	} else {
		printf("ACCESS DENIED\n");
	}
	return 0;
}

int flag (int pin, int secret) {
	if (userToken == 0x1337 && balance == 0x4242 && pin == 0xba5eba11 && secret == 0xbedabb1e) {
		printf("Authenticated to purchase rope chain, sending free flag along with purchase...\n");
		system("/bin/cat flag.txt");
	} else {
		printf("ACCESS DENIED\n");
	}
	return 0;
}

void getInfo () {
	printf("Token: 0x%x\nBalance: 0x%x\n", userToken, balance);
}

int main() {
	gid_t gid = getegid();
	setresgid(gid, gid, gid);
	char name [32];
	printf("--== ROPE CHAIN BLACK MARKET ==--\n");
	printf("LIMITED TIME OFFER: Sending free flag along with any purchase.\n");
	printf("What would you like to do?\n");
	printf("1 - Set name\n");
	printf("2 - Get user info\n");
	printf("3 - Grant access\n");
	int choice;
	scanf("%d\n", &choice);
	if (choice == 1) {
		gets(name);
	} else if (choice == 2) {
		getInfo();
	} else if (choice == 3) {
		printf("lmao no\n");
	} else {
		printf("I don't know what you're saying so get out of my black market\n");
	}
	return 0;
}
```
#### From
