## InterIUT CTF: SMALI, un beau pays [android | 50pts]
> Vous vous retrouvez avec les sources d'une application décompilée, malheureusement vous n'avez que le code SMALI, débrouillez-vous quand même.

#### We were given a .smali file which contains a human readable format of dalvik bytecode to reverse. We can simply provide this to jadx and get a nice looking java equivalent code which we can clearly see the method we need to reverse:

```java
    public boolean checkPassword(String password) {
        try {
            String b = new String(Base64.getDecoder().decode(password.substring(17)));
            if (!b.substring(0, 7).equals(new String(Base64.getDecoder().decode("RU5TSUJTew=="))) || !b.substring(7, 8).equals(password.substring(9, 10)) || !b.substring(8, 14).equals(new String(Base64.getDecoder().decode("bTRsaV8x"))) || !b.substring(14, 15).equals(password.substring(10, 11)) || !b.substring(15, 17).equals("_3") || !b.substring(17, 19).equals(password.substring(8, 10)) || !b.substring(19, 21).equals("Y}")) {
                return false;
            }
            return true;
        } catch (Exception e) {
            return false;
        }
    }
```

#### Analyzing the code, we can see that only `base64decode(password[17:])` is the one being checked on the if statement. Using the hardcoded values, base64 encoded strings and their indexes, we can easily reconstruct the partial flag.

```python
import base64

flag = ['*'] * 20
flag[0:7] = base64.b64decode("RU5TSUJTew==")
flag[8:14] = base64.b64decode("bTRsaV8x")
flag[15:17] = '_3'
flag[19:] = 'Y}'
print(''.join(flag))

#: returns ENSIBS{*m4li_1*_3**Y}
```

## Isn't this how reversing is supposed to be?
#### Now what's left to figure out are the remaining 4 unknown characters. By making an educated guess, we know that the flag is supposed to resemble `smali_is_easy` in l33tspeak. The checks for this indexes in the if statement compares if `base64decode(password[17:])[index] == password[index]`, the catch is that we don't know the characters of `password[:17]`. 

#### After thinking about it for a bit, I thought maybe we could just supply the unknown chars with whatever we want then add the letters we supplied to their mappings on the password string. For example, we can provide `********ASS******RU5TSUJTe1NtNGxpXzFTXzNBU1l9` as the password and it will pass all the checks. 

## When in doubt, bruteforce.
#### But the platform didn't accept the flag. So what I did was to bruteforce the remaining characters. The possible characters are s, S, 5, a, A, 4. Since it is only a small search space, it wouldn't take time to print the possible flags. Here's the python script that I used and luckily for me, the first flag that it printed was the correct flag. 

```python
import base64
from itertools import product

a = product(('s', 'S', '5', 'a', 'A', '4'), repeat = 4)
for i in a:
	b, c, d, e = i

	if b == e and b in 'sS5' and d in 'aA4' and c in 'sS5':
		flag = ['*'] * 20
		flag[0:7] = base64.b64decode("RU5TSUJTew==")
		flag[8:14] = base64.b64decode("bTRsaV8x")
		flag[15:17] = '_3'
		flag[19:] = 'Y}'

		flag[7] = b
		flag[14] = c
		flag[17] = d
		flag[18] = e

		print((''.join(flag)).replace("ENSIBS", "H2G2"))

#: H2G2{sm4li_1s_3asY}
```