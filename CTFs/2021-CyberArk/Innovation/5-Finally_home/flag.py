alphabet = "0123456789ABC10"

def convert_to_base_13(x):
    q,r = divmod(x,13)
    if q == 0:
       return alphabet[r]
    return convert_to_base_13(q) + alphabet[r] 

flag=""
for i in "What a lovely day":
        flag+=convert_to_base_13(ord(i))

print(flag)