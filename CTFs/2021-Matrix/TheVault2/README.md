# The Vault 2 - Matrix Cyber Labs CTF 2021
PWN, 350 Points

## Description

*nc challenges.ctfd.io 30441*

## The Vault 2 Solution

So first, let's connect to application.

```console
┌─[evyatar@parrot]─[/media/shared/ctf/matrix/thevault2]
└──╼ $ nc challenges.ctfd.io 30441
 _____  _              __     __               _  _              ____  
|_   _|| |__    ___    \ \   / /  __ _  _   _ | || |_           |___ \ 
  | |  | '_ \  / _ \    \ \ / /  / _` || | | || || __|  _____     __) |
  | |  | | | ||  __/     \ V /  | (_| || |_| || || |_  |_____|   / __/ 
  |_|  |_| |_| \___|      \_/    \__,_| \__,_||_| \__|          |_____|
                                                                       
 ____  ____  ____  ____  ____  ____  ____ 
||A ||||B ||||C ||||D ||||E ||||F ||||G ||
||__||||__||||__||||__||||__||||__||||__||
|/__\||/__\||/__\||/__\||/__\||/__\||/__\|
 ____  ____  ____  ____  ____  ____  ____ 
||H ||||I ||||J ||||K ||||L ||||M ||||N ||
||__||||__||||__||||__||||__||||__||||__||
|/__\||/__\||/__\||/__\||/__\||/__\||/__\|
 ____  ____  ____  ____  ____  ____  ____ 
||O ||||P ||||Q ||||R ||||S ||||T ||||U ||
||__||||__||||__||||__||||__||||__||||__||
|/__\||/__\||/__\||/__\||/__\||/__\||/__\|
 ____  ____  ____  ____  ____  ____  ____ 
||* ||||V ||||W ||||X ||||Y ||||Z ||||# ||
||__||||__||||__||||__||||__||||__||||__||
|/__\||/__\||/__\||/__\||/__\||/__\||/__\|


Welcome Agent, we need your help to open a Secure Vault.
This time, More Twisted Vault !!!
We managed to intercept some of the encryption method of the vault.
Be aware, You have one time chance to submit the password
Good luck !!!

*************** Main Menu ***************
*                                       *
*  [ 1 ] ---- Encrypt a Letter          *
*  [ 2 ] ---- Print Encrypted Password  *
*  [ 3 ] ---- Submit Password           *
*  [-1 ] ---- Quit                      *
*                                       *
*****************************************

Enter input:

```

We can see that we have three options.
First, Let's try option 1:

```console
┌─[evyatar@parrot]─[/media/shared/ctf/matrix/thevault2]
└──╼ $nc challenges.ctfd.io 30441
 _____  _              __     __               _  _              ____  
|_   _|| |__    ___    \ \   / /  __ _  _   _ | || |_           |___ \ 
  | |  | '_ \  / _ \    \ \ / /  / _` || | | || || __|  _____     __) |
  | |  | | | ||  __/     \ V /  | (_| || |_| || || |_  |_____|   / __/ 
  |_|  |_| |_| \___|      \_/    \__,_| \__,_||_| \__|          |_____|
                                                                       
 ____  ____  ____  ____  ____  ____  ____ 
||A ||||B ||||C ||||D ||||E ||||F ||||G ||
||__||||__||||__||||__||||__||||__||||__||
|/__\||/__\||/__\||/__\||/__\||/__\||/__\|
 ____  ____  ____  ____  ____  ____  ____ 
||H ||||I ||||J ||||K ||||L ||||M ||||N ||
||__||||__||||__||||__||||__||||__||||__||
|/__\||/__\||/__\||/__\||/__\||/__\||/__\|
 ____  ____  ____  ____  ____  ____  ____ 
||O ||||P ||||Q ||||R ||||S ||||T ||||U ||
||__||||__||||__||||__||||__||||__||||__||
|/__\||/__\||/__\||/__\||/__\||/__\||/__\|
 ____  ____  ____  ____  ____  ____  ____ 
||* ||||V ||||W ||||X ||||Y ||||Z ||||# ||
||__||||__||||__||||__||||__||||__||||__||
|/__\||/__\||/__\||/__\||/__\||/__\||/__\|


Welcome Agent, we need your help to open a Secure Vault.
This time, More Twisted Vault !!!
We managed to intercept some of the encryption method of the vault.
Be aware, You have one time chance to submit the password
Good luck !!!

*************** Main Menu ***************
*                                       *
*  [ 1 ] ---- Encrypt a Letter          *
*  [ 2 ] ---- Print Encrypted Password  *
*  [ 3 ] ---- Submit Password           *
*  [-1 ] ---- Quit                      *
*                                       *
*****************************************

Enter input:
1
Please enter a letter to encrypt
A
Your encrypted letter is: U
Based on: 2598126122

Enter input:
1
Please enter a letter to encrypt
A
Your encrypted letter is: D
Based on: 1713870629

Enter input:
1
Please enter a letter to encrypt
B
Your encrypted letter is: U
Based on: 169132671
```

Let's try option 2:
```console
 _____  _              __     __               _  _              ____  
|_   _|| |__    ___    \ \   / /  __ _  _   _ | || |_           |___ \ 
  | |  | '_ \  / _ \    \ \ / /  / _` || | | || || __|  _____     __) |
  | |  | | | ||  __/     \ V /  | (_| || |_| || || |_  |_____|   / __/ 
  |_|  |_| |_| \___|      \_/    \__,_| \__,_||_| \__|          |_____|
                                                                       
 ____  ____  ____  ____  ____  ____  ____ 
||A ||||B ||||C ||||D ||||E ||||F ||||G ||
||__||||__||||__||||__||||__||||__||||__||
|/__\||/__\||/__\||/__\||/__\||/__\||/__\|
 ____  ____  ____  ____  ____  ____  ____ 
||H ||||I ||||J ||||K ||||L ||||M ||||N ||
||__||||__||||__||||__||||__||||__||||__||
|/__\||/__\||/__\||/__\||/__\||/__\||/__\|
 ____  ____  ____  ____  ____  ____  ____ 
||O ||||P ||||Q ||||R ||||S ||||T ||||U ||
||__||||__||||__||||__||||__||||__||||__||
|/__\||/__\||/__\||/__\||/__\||/__\||/__\|
 ____  ____  ____  ____  ____  ____  ____ 
||* ||||V ||||W ||||X ||||Y ||||Z ||||# ||
||__||||__||||__||||__||||__||||__||||__||
|/__\||/__\||/__\||/__\||/__\||/__\||/__\|


Welcome Agent, we need your help to open a Secure Vault.
This time, More Twisted Vault !!!
We managed to intercept some of the encryption method of the vault.
Be aware, You have one time chance to submit the password
Good luck !!!

*************** Main Menu ***************
*                                       *
*  [ 1 ] ---- Encrypt a Letter          *
*  [ 2 ] ---- Print Encrypted Password  *
*  [ 3 ] ---- Submit Password           *
*  [-1 ] ---- Quit                      *
*                                       *
*****************************************

Enter input:
2
Encrypted password: WMNMGBORYCLUXPZMHQCXZWWYHDNNMPJSCBYWELSXJERMZFUMJLDE
Enter input:
```

If we select option 3 - we need to submit the password.

as we can see - If we choose option 1 we will get an option to encrypt a letter.

We need to understand how to get letter U from letter A (Like example above) using the number (based on).

So we know that the output should be a letter - means our calculation should use %26 and +-0x41 ('A'), so:

```c
(N + c - 0x41) % 26 + 0x41 = <Encrypt letter>
```

Where
N-Based on number
c-Input

Great, Now we know how encryption works.
Based on the numbers its looks like random number.

According the hints we can see that "This time, More Twisted Vault !!!..."
So I focus on analyzing the Mersenne Twister MT19937 - which is the most widely used PRNG (using python).
For this purpose (according [(attacking_a_random_number_generator)](https://www.schutzwerk.com/en/43/posts/attacking_a_random_number_generator/)), we need to clone an instance of MT19937 – by far the most widely used PRNG – given 624 consecutive outputs.

So we need to get 624 consecutive outputs from the server.

Let's write python code to do it (we also write the output to data.txt):

```python
import socket


def write_generated_numbers_to_file(file_name):
	print("Writting 624 consecutive outputs to %s..." % file_name)
	with open(file_name,"w") as f:
        	f.write('\r\n'.join(based_on))

#Contains 624 outputs of based on
based_on=[]

TCP_IP = 'challenges.ctfd.io'
TCP_PORT = 30441
BUFFER_SIZE = 2048
MESSAGE = "1\n" # Encrypt letter
ENC_LETTER='A\n'
TOTAL_OUTPUTS=624

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((TCP_IP, TCP_PORT))

data = s.recv(BUFFER_SIZE)
print(data)
s.send(MESSAGE)
data = s.recv(BUFFER_SIZE)

print(data)
s.send(ENC_LETTER)
data = s.recv(BUFFER_SIZE)
print(data)

print("Collecting %s consecutive outputs..." % TOTAL_OUTPUTS)
#Get the first based on
based_on.append(data.split('\n')[1].split(':')[1].strip())

i=1
while i<TOTAL_OUTPUTS: # Get the next 623 based on
	s.send(MESSAGE)
	data = s.recv(BUFFER_SIZE)
	s.send(ENC_LETTER)
	data = s.recv(BUFFER_SIZE)
	based_on.append(data.split('\n')[1].split(':')[1].strip())
	print(data)
	i+=1
	print("%s/%s" % (str(i),str(TOTAL_OUTPUTS)))


write_generated_numbers_to_file("data.txt")
```

Next, I found the following tool in github
*"Predict MT19937 PRNG, from preceding 624 generated numbers. There is a specialization for the "random" of Python* *standard library."*  [(mersenne-twister-predictor)](https://github.com/kmyk/mersenne-twister-predictor)

So Let's install the tool:
```console
┌─[evyatar@parrot]─[/media/shared/ctf/matrix/thevault2]
└──╼ $pip3 install mersenne-twister-predictor
Collecting mersenne-twister-predictor
  Downloading mersenne_twister_predictor-0.0.4-py3-none-any.whl (4.2 kB)
Installing collected packages: mersenne-twister-predictor
Successfully installed mersenne-twister-predictor-0.0.4
```

Let's run the tool that we just installed on the file (data.txt) that we created before which contains 624 generated numbers.
```console
┌─[evyatar@parrot]─[/media/shared/ctf/matrix/thevault2]
└──╼ $head -n 624 data.txt > known.txt
┌─[evyatar@parrot]─[/media/shared/ctf/matrix/thevault2]
└──╼ $cat known.txt | mt19937predict | head -n 376 > predicted.txt

```

Great, now predicted.txt file contains the predicted numbers from data.txt.
Let's just append it to our code - call ```mt19937predict``` right after modifying our data.txt file.

```python
import socket
import os


def write_generated_numbers_to_file(file_name):
	print("Writting 624 consecutive outputs to %s..." % file_name)
	with open(file_name,"w") as f:
        	f.write('\r\n'.join(based_on))

def generate_predicted_numbers():
	print("Creating predicted.txt...")
	os.system("head -n 624 data.txt > known.txt")
	os.system("cat known.txt | mt19937predict | head -n 376 > predicted.txt")

#Contains 624 outputs of based on
based_on=[]

TCP_IP = 'challenges.ctfd.io'
TCP_PORT = 30441
BUFFER_SIZE = 2048
MESSAGE = "1\n" # Encrypt letter
ENC_LETTER='A\n'
TOTAL_OUTPUTS=624

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((TCP_IP, TCP_PORT))

data = s.recv(BUFFER_SIZE)
print(data)
s.send(MESSAGE)
data = s.recv(BUFFER_SIZE)

print(data)
s.send(ENC_LETTER)
data = s.recv(BUFFER_SIZE)
print(data)

print("Collecting %s consecutive outputs..." % TOTAL_OUTPUTS)
#Get the first based on
based_on.append(data.split('\n')[1].split(':')[1].strip())

i=1
while i<TOTAL_OUTPUTS: # Get the next 623 based on
	s.send(MESSAGE)
	data = s.recv(BUFFER_SIZE)
	s.send(ENC_LETTER)
	data = s.recv(BUFFER_SIZE)
	based_on.append(data.split('\n')[1].split(':')[1].strip())
	print(data)
	i+=1
	print("%s/%s" % (str(i),str(TOTAL_OUTPUTS)))


write_generated_numbers_to_file("data.txt")
generate_predicted_numbers()
```

So as we know - If we choose option 1 624 times the application generate 624 random numbers, and If we choose option 2 right after option 1, Our guess is that the application will encrypt each letter from the password with the next genereated number.

So we need our code send option 1 624 times and right after send option 2 to get the encrypted password.

Let's code it:
```python
import socket
import os


def write_generated_numbers_to_file(file_name):
	print("Writting 624 consecutive outputs to %s..." % file_name)
	with open(file_name,"w") as f:
        	f.write('\r\n'.join(based_on))

def generate_predicted_numbers():
	print("Creating predicted.txt...")
	os.system("head -n 624 data.txt > known.txt")
	os.system("cat known.txt | mt19937predict | head -n 376 > predicted.txt")

#Contains 624 outputs of based on
based_on=[]

TCP_IP = 'challenges.ctfd.io'
TCP_PORT = 30441
BUFFER_SIZE = 2048
MESSAGE = "1\n" # Encrypt letter
ENC_LETTER='A\n'
TOTAL_OUTPUTS=624

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((TCP_IP, TCP_PORT))

data = s.recv(BUFFER_SIZE)
print(data)
s.send(MESSAGE)
data = s.recv(BUFFER_SIZE)

print(data)
s.send(ENC_LETTER)
data = s.recv(BUFFER_SIZE)
print(data)

print("Collecting %s consecutive outputs..." % TOTAL_OUTPUTS)
#Get the first based on
based_on.append(data.split('\n')[1].split(':')[1].strip())

i=1
while i<TOTAL_OUTPUTS: # Get the next 623 based on
	s.send(MESSAGE)
	data = s.recv(BUFFER_SIZE)
	s.send(ENC_LETTER)
	data = s.recv(BUFFER_SIZE)
	based_on.append(data.split('\n')[1].split(':')[1].strip())
	print(data)
	i+=1
	print("%s/%s" % (str(i),str(TOTAL_OUTPUTS)))


write_generated_numbers_to_file("data.txt")
generate_predicted_numbers()

print("Get the encrypted string...")
s.send("2\n")
data = s.recv(BUFFER_SIZE)
encrypted_str=data.split(':')[1].strip()
print(data)
```

Now, When we have encrypted password, predicted numbers and we can try to find the password according to the following calculation:
```c
(N + c - 0x41) % 26 + 0x41 = <Encrypt letter>
```

We know that N is the next predicted number (what we have on predict.txt), c is the letter we need to guess and <Encrypt letter> is letter from the encrypted password.

So we can guess the password and send it to the application to get the flag:
```python
import socket
import string
import os


def write_generated_numbers_to_file(file_name):
	print("Writting 624 consecutive outputs to %s..." % file_name)
	with open(file_name,"w") as f:
        	f.write('\r\n'.join(based_on))

def generate_predicted_numbers():
	print("Creating predicted.txt...")
	os.system("head -n 624 data.txt > known.txt")
	os.system("cat known.txt | mt19937predict | head -n 376 > predicted.txt")

def get_predicted_numbers():
	with open("predicted.txt") as f:
    		content = f.readlines()
	return [x.strip() for x in content]

def guess_password(predicted_numbers, encrypted_str):
	predict_index=0
	password=""
	for i in range(53):
        	res = guess_letter(encrypted_str[i], predicted_numbers[predict_index])
        	password+=res
        	predict_index+=1

	return password


def guess_letter(encrypted_char, predict):
        upper_characters = string.ascii_uppercase # The password contains only upper case

	for c in upper_characters:
                if ((int(predict) + ord(c) - 0x41) % 26) + 0x41 == ord(encrypted_char):
                        return c
	return ""

#Contains 624 outputs of based on
based_on=[]

TCP_IP = 'challenges.ctfd.io'
TCP_PORT = 30441
BUFFER_SIZE = 2048
MESSAGE = "1\n" # Encrypt letter
ENC_LETTER='A\n'
TOTAL_OUTPUTS=624

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((TCP_IP, TCP_PORT))

data = s.recv(BUFFER_SIZE)
print(data)
s.send(MESSAGE)
data = s.recv(BUFFER_SIZE)

print(data)
s.send(ENC_LETTER)
data = s.recv(BUFFER_SIZE)
print(data)

print("Collecting %s consecutive outputs..." % TOTAL_OUTPUTS)
#Get the first based on
based_on.append(data.split('\n')[1].split(':')[1].strip())

i=1
while i<TOTAL_OUTPUTS: # Get the next 623 based on
	s.send(MESSAGE)
	data = s.recv(BUFFER_SIZE)
	s.send(ENC_LETTER)
	data = s.recv(BUFFER_SIZE)
	based_on.append(data.split('\n')[1].split(':')[1].strip())
	print(data)
	i+=1
	print("%s/%s" % (str(i),str(TOTAL_OUTPUTS)))


write_generated_numbers_to_file("data.txt")
generate_predicted_numbers()

print("Get the encrypted string...")
s.send("2\n") # Print encrypted password
data = s.recv(BUFFER_SIZE)
encrypted_str=data.split(':')[1].strip()
print(data)


print("Guess the password...")
predicted_numbers = get_predicted_numbers()
password=guess_password(predicted_numbers, encrypted_str)
print("Submit password %s" % password)


s.send("3\n") # Submit password
data = s.recv(BUFFER_SIZE)
print(data)
s.send(password + "\n")
data = s.recv(BUFFER_SIZE)
print(data)
s.close()
```

So let's run the script to get the flag:

```console
┌─[evyatar@parrot]─[/media/shared/ctf/matrix/thevault2]
└──╼ $ python vault2.py 
 _____  _              __     __               _  _              ____  
|_   _|| |__    ___    \ \   / /  __ _  _   _ | || |_           |___ \ 
  | |  | '_ \  / _ \    \ \ / /  / _` || | | || || __|  _____     __) |
  | |  | | | ||  __/     \ V /  | (_| || |_| || || |_  |_____|   / __/ 
  |_|  |_| |_| \___|      \_/    \__,_| \__,_||_| \__|          |_____|
                                                                       
 ____  ____  ____  ____  ____  ____  ____ 
||A ||||B ||||C ||||D ||||E ||||F ||||G ||
||__||||__||||__||||__||||__||||__||||__||
|/__\||/__\||/__\||/__\||/__\||/__\||/__\|
 ____  ____  ____  ____  ____  ____  ____ 
||H ||||I ||||J ||||K ||||L ||||M ||||N ||
||__||||__||||__||||__||||__||||__||||__||
|/__\||/__\||/__\||/__\||/__\||/__\||/__\|
 ____  ____  ____  ____  ____  ____  ____ 
||O ||||P ||||Q ||||R ||||S ||||T ||||U ||
||__||||__||||__||||__||||__||||__||||__||
|/__\||/__\||/__\||/__\||/__\||/__\||/__\|
 ____  ____  ____  ____  ____  ____  ____ 
||* ||||V ||||W ||||X ||||Y ||||Z ||||# ||
||__||||__||||__||||__||||__||||__||||__||
|/__\||/__\||/__\||/__\||/__\||/__\||/__\|


Welcome Agent, we need your help to open a Secure Vault.
This time, More Twisted Vault !!!
We managed to intercept some of the encryption method of the vault.
Be aware, You have one time chance to submit the password
Good luck !!!

*************** Main Menu ***************
*                                       *
*  [ 1 ] ---- Encrypt a Letter          *
*  [ 2 ] ---- Print Encrypted Password  *
*  [ 3 ] ---- Submit Password           *
*  [-1 ] ---- Quit                      *
*                                       *
*****************************************

Enter input:

Please enter a letter to encrypt

Your encrypted letter is: J
Based on: 3133620057

Enter input:

Collecting 624 consecutive outputs...
Your encrypted letter is: V
Based on: 2788662625

Enter input:

2/624
Your encrypted letter is: C
Based on: 484667900

Enter input:

3/624
Your encrypted letter is: C
Based on: 3947743230

Enter input:

4/624
Your encrypted letter is: E
Based on: 4103919044

Enter input:

5/624
Your encrypted letter is: K
Based on: 2878021078

Enter input:

....

623/624
Your encrypted letter is: J
Based on: 4029688269

Enter input:

24/624
Writting 624 consecutive outputs to data.txt...
Creating predicted.txt...
Get the encrypted string...
Encrypted password: TVNDYAUZDUOJNLPFFDINQWWJAHFZTMQEKRRWLSBGEWIUDRAROKKB
Enter input:

Guess the password...
Submit password SEEMSLIKEYOUUNTWISTEDTHEMERSENNETWISTERPRNGALGOIRTHM
Please submit the password

Congrats !!!
MCL{M3rSenne_Tw1s7er_1s_STi11_Prn9_4ft3r_A11}
```