## Arab Sec Cyber Wargames: check
##### category: Reverse Engineering
##### *tl;dr: control environment variables to print out flag*

#### [hacker's log]: It's almost been a year after I played a CTF due to the fact that the old laptop I was using broke. Now that I was given a new one, I wanted to play CTFs immediately but forgot how to solve challs. For real this time, I want to polish my skills in RE and PWN.

## Analysis
#### Running the file utility on the binary displays the following results, then running it for the first time shows something about checking the machine:
```
$ file check
check: ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=59113482c142bbe39071d77bf2a2a1bc0c4fe948, for GNU/Linux 3.2.0, stripped

$ ./check
[-] Checking machine...
[×] Machine not OK.
```
#### We have a stripped binary which is a pain in the ass to reverse. Loaded up the binary in IDA (first time ill be using it) and thoroughly reversed each part of the program. 
