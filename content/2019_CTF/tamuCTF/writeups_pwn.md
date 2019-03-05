# tamuCTF: pwn

## pwn1
### Assumeably the easiest among the pwn challenges, I started the approach by running the 32-bit executable. We get asked by a prompt which reads: 
```Stop! Who would cross the Bridge of Death must answer me these questions three, ere the other side he see.
What... is your name?```
### Given the prompt and disassembly from gdb, I deduced that there is a string check for these questions. So what I did was use the command line utility *strings* on the binary and I got answers for the first two questions:
```Stop! Who would cross the Bridge of Death must answer me these questions three, ere the other side he see. 
What... is your name?```
