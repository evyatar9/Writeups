# Safe Opener - picoCTF 2022 - CMU Cybersecurity Competition
Reverse Engineering, 100 Points

## Description

![‏‏info.JPG](images/info.JPG)
 
## Safe Opener Solution

By observing the [attached code](./SafeOpener.java) we can see the following function ```openSafe```:
```java
public static boolean openSafe(String password) {
        String encodedkey = "cGwzYXMzX2wzdF9tM18xbnQwX3RoM19zYWYz";
        
        if (password.equals(encodedkey)) {
            System.out.println("Sesame open");
            return true;
        }
        else {
            System.out.println("Password is incorrect\n");
            return false;
        }
    }
```

We can see the Base64 password ```cGwzYXMzX2wzdF9tM18xbnQwX3RoM19zYWYz```, By decoding it we get ```pl3as3_l3t_m3_1nt0_th3_saf3``` so the flag is ```picoCTF{pl3as3_l3t_m3_1nt0_th3_saf3}```.