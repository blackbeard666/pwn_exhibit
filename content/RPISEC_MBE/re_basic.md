### Tools and Basic Reverse Engineering

#### The first part of the course starts with a basic introduction of what reverse engineering is and what are the common tools used to reverse engineer (or RE) a binary. As discussed in the lecture slides, below are the tools that can be used for RE along with a short description of what it does which will be essential in solving the crackme challenges provided:
```
Hex Editors/Viewers
  xxd : creates a hex dump of a given file or standard input.
ASCII Readable Hex
  strings : print the strings of printable characters in files.
Files and File formats
  readelf : displays information about ELF files.
  file : tests each argument in an attempt to classify it.
Disassembly
  objdump :  displays information from object files.
```
#### I'll also be using NSA's software RE tool, GHIDRA, in some problems, just to familiarize myself with the tool and be able to use it for ctfs in the upcoming days. Now that we know some of the basic tools and their functionalities, let's head on to the crackmes:

#### crackme0x00a
#### As listed on the slides, the challenge can be solvable using ```xxd``` and ```strings```, so we'll do that. First, we use the xxd utility to print a hex dump of the binary and search for interesting things:
```
$ xxd crackme0x00a
  [...]
  00000640: 456e 7465 7220 7061 7373 776f 7264 3a20  Enter password: 
  00000650: 0025 7300 436f 6e67 7261 7473 2100 5772  .%s.Congrats!.Wr
  00000660: 6f6e 6721 0000 0000 011b 033b 3000 0000  ong!.......;0...
  [...]
  00001000: c683 0408 d683 0408 e683 0408 f683 0408  ................
  00001010: 0684 0408 1684 0408 2684 0408 0000 0000  ........&.......
  00001020: 0000 0000 6730 3064 4a30 4221 0000 0000  ....g00dJ0B!....
```
#### We see that the binary has a prompt which asks us to enter a password, and the password is this ```g00dJ0B``` string we found. We can also use strings to easily print out the string.
```
$ strings crackme0x00a
  [...]
  Enter password: 
  Congrats!
  Wrong!
  ;*2$"
  g00dJ0B!
```
#### After getting the information we needed, let's run the binary and input what we have:
```
$ ./cracme0x00a
  Enter a password:
  g00dJ0B!
  Congrats!
```

#### crackme0x00b
#### This challenge can be solved using strings, but we need to specify some arguments. Let's take a look:
```
$ strings crackme0x00b
  /lib/ld-linux.so.2
  em!!
  __gmon_start__
  libc.so.6
  _IO_stdin_used
  __isoc99_scanf
  puts
  printf
  wcscmp
  __libc_start_main
```
#### The string ```em!!``` is interesting, so we'll try inputting it to the binary but we get nothing out of it.
```
$ ./crackme0x00b
  Enter password:
  em!!
  Wrong!
```
#### Since we need to specify arguments in order to solve the challenge, let's take a look the the options of the strings utility
```
$ strings --help
  Display printable strings in [file(s)] (stdin by default)
   The options are:
   [...]
   -e --encoding={s,S,b,l,B,L} Select character size and endianness:
      s = 7-bit, S = 8-bit, {b,l} = 16-bit, {B,L} = 32-bit
```
#### We can use the ```-e``` then specify the 32-bit ```L``` option, which is 32-bit little endian.
```
$ strings -e L crackme0x00b
  w0wgreat
```
#### And we have the password for the binary:
```
./crackme0x00b
  Enter a password:
  w0wgreat
  Congrats!
```



