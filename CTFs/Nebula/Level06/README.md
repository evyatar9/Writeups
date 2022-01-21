# Nebula - [LEVEL 06](https://exploit.education/nebula/level-06/)

Level Description:

![level.JPG](images/level.JPG)

# Nebula - [LEVEL 06](https://exploit.education/nebula/level-06/) - Solution

According to the challenge description, we need to find the password of ```flag06``` user, Earlier, passwords were stored in ```/etc/passwd``` file, because ```/etc/passwd``` accessible by everyone - the passwords were later moved to ```/etc/shadow```.

By observing the file ```/etc/passwd``` we found the hashed password of ```flag06```:

![passwd.JPG](images/passwd.JPG)

Let's save the hash:

![hash.JPG](images/hash.JPG)

By cracking this hash using ```john``` we get the password ```hello```, Let's login as ```flag06``` using this password to run ```getflag```:

![flag.JPG](images/flag.JPG)


