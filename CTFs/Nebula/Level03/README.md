# Nebula - [LEVEL 03](https://exploit.education/nebula/level-03/)

Level Description:

![level.JPG](images/level.JPG)

# Nebula - [LEVEL 03](https://exploit.education/nebula/level-03/) - Solution

By observing ```/home/flag03``` directory we can see the following files:

![home.JPG](images/home.JPG)

```writable.sh``` file contains the following code:

![writable.JPG](images/writable.JPG)

According to the challenge description we can assume that this script will run by crontab, Let's create on ```writable.d``` directory our script to run ```getflag``` command and write the result of the command to the same directory:
```console
getflag > /home/flag03/writable.d/result
```

Wait a couple of minutes and we get:

![flag.JPG](images/flag.JPG) 
