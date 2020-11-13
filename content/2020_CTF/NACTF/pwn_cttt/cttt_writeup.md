## NACTF: covid tracker tracker tracker [pwn]
![](cttt_desc.png)

## Note to self:
#### I didn't solve this during the duration of the competition, but rather after reading some of the writeups. I did an analysis of HK's [writeup](https://gist.github.com/hkraw/3b518632e18681669d09e7ccc1db2cba) but made some tweaks of my own, particularly in the last stages of the exploit since I couldn't fully understand how his worked. This is the first heap exploit that I will be covering, thus I will try to make it as understandable as I can, so it may serve as a future reference for me when doing more heap in the future. There's still a long way of learning to go, just focus. You got this. 

## Static Analysis
#### For this challenge, we were given the challenge binary, the libc it uses, and the linker to work with. First thing I did was to run checksec on the binary, and I was not surprised to see almost every protection (except PIE) turned on. 

```
$ checksec cttt
[*] '/home/chooey/Desktop/NACTF/pwn_cttt/cttt'
	Arch: amd64-64-little
	RELRO: Full RELRO
	Stack: Canary found
	NX: NX enabled
	PIE: No PIE (0x400000)
```

#### I then used patchelf to change the linker that the binary will use. Next, using strings I tried to determine the glibc version which is used. The glibc version is an important part of (every) heap exploitation challenge, as certain glibc versions have countermeasures against heap allocator misuse. Knowing which glibc version is being used will help us narrow down what vulnerabilities we are able to leverage and which techniques we are able to use.

```
$ patchelf --set-interpreter ./ld-linux-x86-64.so.2 ./cttt
$ strings libc.so.6 | grep version
[...]
GNU C Library (Ubuntu GLIBC 2.27-3ubuntu1) stable release version 2.27
```

#### Know we now that the challenge uses glibc 2.27, a noteable feature of this version is the implementation of the tcache bins. After that, I proceeded to test out my new friend `pwninit`. Reading some heap writeups, I plan to use pwninit to unstrip the libc (to make it easier for us to debug) and help us retrieve the linker used (if it wasn't provided). I then did a quick test run of what the binary does. It presents us a menu-style challenge. 
![](cttt_menu.png)

#### I opened the binary in GHIDRA in order to have a better understanding of its inner workings. There are four functions of interest for us: add, edit, delete, and list. The decompiled code and explanation of what it does are as follows:

## add()
![](add_ghidra.png)

#### From what we can see, there is a limit to how many trackers can be allocated and it caps at 0x10 (16). Every allocation is of size 0x40 and each pointer is stored in a global variable called urls. 

## edit()
![](edit_ghidra.png)

#### edit simply allows us to, well, edit the content (body) of the chunk (tracker) that we specify. It only allows input of size 0x40 and null terminates it. 

## delete()
![](delete_ghidra.png)

#### This part is where it starts to get interesting. Before freeing a chunk, the function first checks if it's entry in the is_deleted array is set to 1; that is to say that the chunk has already been deleted so it shouldn't do anything with it. This is simply a protective measure against double frees. In the case that it hasn't been freed yet, it proceeds to free the said chunk and set it's is_deleted entry to 1. The problem relies with the fact that after freeing the chunk, it didn't NULL out the pointer thus leading to a `use-after-free` vulnerability.

#### insert use-after-free explanation here.

## list()
![](list_ghidra.png)

#### it just prints out the current allocated chunks and the data that each chunk holds.

## Creating utilities
#### Given this information, I began to write the first parts of my exploit script to interact with the challenge binary. We need to specify the LD_PRELOAD env variable in order to make sure that the binary uses the correct version of libc.

```python
from pwn import *

#: Connect to challenge process

binary = ELF('./cttt', checksec = False)
libc = ELF('./libc.so.6', checksec = False)
p = process('./cttt', env = {'LD_PRELOAD' : './libc.so.6'})
#p = remote('challenges.ctfd.io', 30252)
script = '''
break *add + 91
break *edit
break *delete + 122
'''
gdb.attach(p.pid, gdbscript=script)

#: Helper functions
def add_tracker():
	print(p.recvuntil('> '))
	p.sendline('1')

def edit_tracker(tracker_number, url):
	print(p.recvuntil('> '))
	p.sendline('2')
	p.sendlineafter('?\n', tracker_number)
	p.sendlineafter('?\n', url)

def delete_tracker(tracker_number):
	print(p.recvuntil('> '))
	p.sendline('3')
	p.sendlineafter('?\n', str(tracker_number))

def list_trackers():
	print(p.recvuntil('> '))
	p.sendline('4')
	print(p.recv())
```

#### Next part here.