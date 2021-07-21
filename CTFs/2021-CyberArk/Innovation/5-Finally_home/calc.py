first_args=open('first_and_args').readlines()
last_minus=open('last_minus_calc').readlines()

answer=""
for i in range(len(first_args)):
    for char in range(255):
        if ((char ^ -1) & int(first_args[i].rstrip()) | (char & - (int(first_args[i].rstrip()) + 1) )) - int(last_minus[i].rstrip()) == 0:
            answer+=chr(char)

print(answer)