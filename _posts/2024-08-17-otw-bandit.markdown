---
layout: post
title: "OverTheWire Bandit"
date: 2024-08-17 +0200
categories: jekyll update
---
Website: [https://overthewire.org/wargames/](https://overthewire.org/wargames/)
```sh
ssh bandit0@bandit.labs.overthewire.org -p 2220
```

## bandit0
- `cat readme`

## bandit1
- `cat ~/-`

## bandit2
- `cat 'spaces in this filename'`

## bandit3
- `cat inhere/...Hiding-From-You`

## bandit4
- use `--` to skip command options: `cat -- -file00`
- print all file contents with a newline

```sh
for i in {00..09}; do
    echo -e "\nfile$i"
    cat -- -file$i
done
# file07: <snip>
```

## bandit5
```sh
for i in {00..19}; do
    echo -e "\nmaybehere$i"
    cat -- maybehere$i
done
```
- print all subdirectories: `ls -Rla`
- files that are executable: `find . -type f -executable`
- files that are 1033 bytes: `find . -type f -size 1033c`
- `cat ./maybehere07/.file2`

## bandit6
- find a file somewhere on the server:
    - owned by user bandit7
    - owned by group bandit6
    - 33 bytes in size
- `find / -type f -user bandit7 -group bandit6 -size 33c 2>/dev/null`
- `cat /var/lib/dpkg/info/bandit7.password`

## bandit7
- take a closer look at data.txt: `scp -P 2220 bandit7@bandit.labs.overthewire.org:~/data.txt data.txt`
- `grep 'millionth' data.txt`

## bandit8
- print only lines that appear only once
- `sort data.txt | uniq -u`

## bandit9
- look for a string with several `=`
- `strings data.txt | grep ===`

## bandit10
- decode base64: `base64 -d data.txt `
- The password is `<snip>`

## bandit11
- decode rot13: `cat data.txt | tr 'A-Za-z' 'N-ZA-Mn-za-m'`
- The password is `<snip>`

## bandit12
- have to do a lot of decompressing with tar, bzip, gzip; use verbose mode to see output
- `file` to check archive format and `mv` to set the proper archive suffix

```sh
mkdir /tmp/ketho
cd /tmp/ketho
cp ~/data.txt data.txt
xxd -r data.txt > data

file data # data: gzip compressed data, was "data2.bin", last modified: Wed Jul 17 15:57:06 2024, max compression, from Unix, original size modulo 2^32 577
mv data data.gz
gzip -dv data.gz # data.gz:         -0.9% -- replaced with data

file data # data: bzip2 compressed data, block size = 900k
bzip2 -d data # bzip2: Can't guess original name for data -- using data.out

file data.out # data.out: gzip compressed data, was "data4.bin", last modified: Wed Jul 17 15:57:06 2024, max compression, from Unix, original size modulo 2^32 20480
mv data.out data.gz
gzip -dv data.gz # data.gz:         98.0% -- replaced with data

file data # data: POSIX tar archive (GNU)
tar -xf data -v # data5.bin

file data5.bin # data5.bin: POSIX tar archive (GNU)
tar -xf data5.bin -v # data6.bin

file data6.bin # data6.bin: bzip2 compressed data, block size = 900k
bzip2 -d data6.bin # bzip2: Can't guess original name for data6.bin -- using data6.bin.out

file data6.bin.out # data6.bin.out: POSIX tar archive (GNU)
tar -xf data6.bin.out -v # data8.bin

file data8.bin # data8.bin: gzip compressed data, was "data9.bin", last modified: Wed Jul 17 15:57:06 2024, max compression, from Unix, original size modulo 2^32 49
mv data8.bin data8.gz
gzip -dv data8.gz # data8.gz:        -4.1% -- replaced with data8

file data8 # data8: ASCII text
cat data8

# The password is <snip>
```

## bandit13
- `cat sshkey.private`
- had to recreate .ssh folder, something was wrong with permissions on Windows
- download/copy to bandit14.pem
- `ssh -i ~\.ssh\bandit14.pem bandit14@bandit.labs.overthewire.org -p 2220`
- `cat /etc/bandit_pass/bandit14`
- first need to use ssh key, but can use password afterwards

## bandit14
- `cat /etc/bandit_pass/bandit14 | nc localhost 30000`

## bandit15
- need to use [openssl](https://linux.die.net/man/1/openssl) `s_client` to connect with SSL/TLS and `-quiet` to see the response
- `cat /etc/bandit_pass/bandit15 | openssl s_client -connect localhost:30001 -quiet`

## bandit16
- do a portscan and ignore warnings

```sh
for i in {31000..32000}; do
    (echo > /dev/tcp/localhost/$i) >& /dev/null && echo "Port $i open"
done
```
- port 31518 returned the same password from level 16, 31790 a private key

```sh
cat /etc/bandit_pass/bandit16 | openssl s_client -connect localhost:31518 -quiet
cat /etc/bandit_pass/bandit16 | openssl s_client -connect localhost:31790 -quiet
```

```pem
-----BEGIN RSA PRIVATE KEY-----
<snip>
-----END RSA PRIVATE KEY-----
```

## bandit17
- `ssh -i ~\.ssh\bandit17.pem bandit17@bandit.labs.overthewire.org -p 2220`
- `diff passwords.old passwords.new`

```
42c42
< bSrACvJvvBSxEM2SGsV5sn09vc3xgqyp
---
> <snip>
```

## bandit18
- I immediately got logged out; apparently can just send a command
- `ssh bandit18@bandit.labs.overthewire.org -p 2220 cat readme`

## bandit19
The setuid binary lets you run a command as bandit20
```sh
ls -la
-rwsr-x---  1 bandit20 bandit19 14880 Jul 17 15:57 bandit20-do
```
`./bandit20-do cat /etc/bandit_pass/bandit20`

## bandit20
The same as bandit 19 but then with networking. The setuid binary makes a connection to localhost to the given port.
```sh
# server
nc -lp 3017 < /etc/bandit_pass/bandit20
# client
./suconnect 3017
```

## bandit21
There is a cronjob that runs every minute which runs a script `/usr/bin/cronjob_bandit22.sh`. The script writes the password to a temporary file
```sh
cat /etc/cron.d/cronjob_bandit22
@reboot bandit22 /usr/bin/cronjob_bandit23.sh &> /dev/null
* * * * * bandit22 /usr/bin/cronjob_bandit22.sh &> /dev/null
```
```sh
cat /usr/bin/cronjob_bandit22.sh
#!/bin/bash
chmod 644 /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
```
```sh
cat /etc/bandit_pass/bandit22 > /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
bandit21@bandit:/etc/cron.d$ cat /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
```

## bandit22
- This cronjob also runs every minute

```sh
cat /etc/cron.d/cronjob_bandit23
@reboot bandit23 /usr/bin/cronjob_bandit23.sh  &> /dev/null
* * * * * bandit23 /usr/bin/cronjob_bandit23.sh  &> /dev/null
```
- `cat /usr/bin/cronjob_bandit23.sh`

```sh
#!/bin/bash

myname=$(whoami)
mytarget=$(echo I am user $myname | md5sum | cut -d ' ' -f 1)

echo "Copying passwordfile /etc/bandit_pass/$myname to /tmp/$mytarget"

cat /etc/bandit_pass/$myname > /tmp/$mytarget
```
- The script seems to make an md5 hash of `I am user bandit23` which will be the temp file for the password.

```sh
cat /tmp/$(echo I am user bandit23 | md5sum | cut -d ' ' -f 1)
```
