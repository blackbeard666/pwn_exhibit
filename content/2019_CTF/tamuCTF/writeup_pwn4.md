## tamuCTF: pwn4
##### *tl;dr: ret2libc + unintended solution*
#### This challenge was a bit odd, not only because I was unfamiliar with the intended way of solving it but because of the unintended solution. Maybe the challenge creators have overlooked it? At this point, I'd want to explain the intended solution first to have a more in-depth discussion of what it is and how it is executed after which is just showing how to do the intended way. First things first, check for the security properties of the binary using *checksec*:
```
$ checksec pwn4
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```
#### We can see that NX is enabled, this means that the stack has its non executable properties turned on, we can't execute code we put in the stack, thus we can't get a shell using shellcode. No canary is on the stack tho, which means we can still smash it with good 'ol buffer overflow. But before we jump to which exploit method to do, we have to play around with the binary.
