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
