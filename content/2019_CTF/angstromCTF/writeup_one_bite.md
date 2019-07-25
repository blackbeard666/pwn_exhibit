## angstromCTF: One Bite
##### category: Reverse Engineering
> Whenever I have friends over, I love to brag about things that I can eat in a single bite. Can you give this program a tasty flag that fits the bill?

#### We are given a binary that accepts input and checks if we provided the correct flag. Since this is a reverse engineering task (and I still have a lot to learn with assembly), we load the binary into GHIDRA and quickly examine the logic in its main function:

## Source Code Analysis
```c
undefined8 main(void)

{
  long lVar1;
  int iVar2;
  size_t sVar3;
  long in_FS_OFFSET;
  int index;
  byte buffer [40];
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  puts("Give me a flag to eat: ");
  fgets((char *)buffer,0x22,stdin);
  index = 0;
  while( true ) {
    sVar3 = strlen((char *)buffer);
    if (sVar3 <= (ulong)(long)index) break;
    buffer[(long)index] = buffer[(long)index] ^ 0x3c;
    index = index + 1;
  }
  iVar2 = strcmp((char *)buffer,"]_HZGUcHTURWcUQc[SUR[cHSc^YcOU_WA");
  if (iVar2 == 0) {
    puts("Yum, that was a tasty flag.");
  }
  else {
    puts("That didn\'t taste so good :(");
  }
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```
#### From what we can see, a buffer for user input is initialized for 40 bytes but only reads up to 34, which we assume to be the length of the flag. Then, it performs a while loop that iterates through each character in the buffer and performs an XOR operation with 0x3c (only one byte, hence the wordplay in the challenge title). After the loop breaks, the program proceeds to compare the XOR'ed buffer with a long string of seemingly random characters. It is important to know tho that the string is of the same length as our buffer. 
#### Since we know the reverseability of the XOR operation, we can simply XOR the string which we are comparing to that one byte that was used. For this, I have crafted a simple script to communicate with the challenge server and reciprocate the operation to retrieve the flag.
##### rev.py
```python
from pwn import *

#: Connect to chall server
binary = ELF('./one_bite', checksec=False)
p = binary.process()
context.log_level = 'error'
print(p.recv())

#: Reversed code
encoded_text = ']_HZGUcHTURWcUQc[SUR[cHSc^YcOU_WA'
decoded_text = ''

for letter in encoded_text:
	decoded_text += chr(ord(letter) ^ 0x3c)

print(decoded_text)

#: Send payload
p.sendline(decoded_text)
print(p.recv())
```
#### Run the script, capture the flag! 
```
$ python rev.py
Give me a flag to eat: 

actf{i_think_im_going_to_be_sick}
Yum, that was a tasty flag.
```
