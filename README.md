# Padding Oracle Attack

An exploit for the [Padding Oracle Attack](https://en.wikipedia.org/wiki/Padding_oracle_attack). Tested against ASP.NET, works like a charm. The CBC  mode must use [PKCS7](https://en.wikipedia.org/wiki/Padding_%28cryptography%29#PKCS7) for the padding block.
This is an implementation of this great article [Padding Oracle Attack](https://not.burntout.org/blog/Padding_Oracle_Attack/). Since the article is not very well formated and maybe unclear, I made an explanation in the readme. i advise you to read it if you want to understand the basics of the attack.
This exploit allow block size of 8 or 16 this mean it can be use even if the cipher use AES or DES. You can find instructions to launch the attack [here](https://github.com/mpgn/Padding-Oracle-Attack#options).

I also made a test file `test.py`, you don't need a target to use it :)

## Explanation

I will explain in this part the cryptography behind the attack. To follow this you need to understand the [CBC mode cipher chainning](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_.28CBC.29) or [video link](https://www.youtube.com/watch?v=0D7OwYp6ZEc.) and the operator ⊕. This attack is also a [chosen-ciphertext attack](https://en.wikipedia.org/wiki/Chosen-ciphertext_attack).

Encryption | Decryption
--- | --- 
C<sub>i</sub> = E<sub>k</sub>(P<sub>i</sub> ⊕ C<sub>i-1</sub>), and C<sub>0</sub> = IV | P<sub>i</sub> = D<sub>k</sub>(C<sub>i</sub>) ⊕ C<sub>i-1</sub>, and C<sub>0</sub> = IV

In CBC mode we also need a padding in the case the length of the plaintext doesn't fill all the block. For example we can have this plaintext and the following padding if the length of the block is 8 :

`S|E|C|R|E|T| |M|E|S|S|A|G|E|02|02`

You can notice the length of SECRET MESSAGE is 14 so we need to fill two blocks of CBC equal 16. There are two bytes left, this is where the padding step in. You can see the two last byte 0202. Another example, if the padding had a length of 5, it will be fill with 05|05|05|05|05. Of course there is different way to fill the padding but in our case like most of the case the standard is [PKCS7](https://en.wikipedia.org/wiki/Padding_%28cryptography%29#PKCS7) for the padding block.

If the padding does not match the PKCS7 standard it will produce an error. Example :

`S|E|C|R|E|T| |M|E|S|S|A|G|E|03|03`

When the block will be deciphered there will be a verification to check if the padding is good or not :

`S|E|C|R|E|T| |M|E|S|S|A|G|E|03|03` => Wrong padding <br>
`S|E|C|R|E|T| |M|E|S|S|A|G|E|02|02` => Good padding

Now imagine we can **know** when we have a bad padding and a good padding (the server send an "error padding" or "404 not found" when the padding is wrong etc). We will call this our [Oracle](http://security.stackexchange.com/questions/10617/what-is-a-cryptographic-oracle). The answers he will give us will be :

* good padding
* bad padding

Now we know that, we can construct a block to retrieve one byte of the plaintext, don't forget this is a chosen-ciphertext attack.
An attacker will intercept a cipher text and retrieve byte by byte the plaintext.

* intercepted cipher : C<sub>0</sub> | C<sub>...</sub> | C<sub>i-1</sub> | C<sub>i</sub>
* then build a block like this :

C'<sub>i-1</sub> = C<sub>i-1</sub> ⊕ 00000001 ⊕ 0000000X | C<sub>i</sub>

Where X is a char between `chr(0-256)`. 

* then he sends C'<sub>i-1</sub> \| C<sub>i</sub> to the oracle. The oracle will decrypt like this :

D<sub>k</sub>(C<sub>i</sub>) ⊕ C'<sub>i-1</sub>  <br>
= D<sub>k</sub>(C<sub>i</sub>) ⊕ C<sub>i-1</sub> ⊕ 00000001 ⊕ 0000000X <br>
= P<sub>i</sub> ⊕ 00000001 ⊕ 0000000X <br>

Now there is two possibilities: a padding error or not :

* if we have a padding error :

```
If P'i ⊕ 0000000Y == abcdefg5 then:
    abcdefg0 ⊕ 00000001 = abcdefg5
```
This is a wrong padding, so we can deduce the byte Y is wrong.

* The oracle didn't give us a padding error and we know the byte X is good :

```
If Pi ⊕ 0000000X == abcdefg0 then:
    abcdefg0 ⊕ 00000001 = abcdefg1
```

<hr>

**For the second byte :**


C'<sub>i-1</sub> = C<sub>i-1</sub> ⊕ 00000022 ⊕ 000000YX \| C<sub>i</sub>

And then : 

D<sub>k</sub>(C<sub>i</sub>) ⊕ C'<sub>i-1</sub> <br>
= D<sub>k</sub>(C<sub>i</sub>) ⊕ C<sub>i-1</sub> ⊕ 00000022 ⊕ 000000YX <br>
= P<sub>i</sub> ⊕ 00000001 ⊕ 00000YX <br>

* The oracle didn't give us a padding error and we know the byte X is good :

```
If Pi ⊕ 000000YX == abcdef00 then:
    abcdef00 ⊕ 00000022 = abcdef22
```

etc etc for all the block. You can now launch the python script by reading the next section :)


### Protection 

* Encrypt and MAC your data : http://security.stackexchange.com/questions/38942/how-to-protect-against-padding-oracle-attacks
* Don't give error message like "Padding error", "MAC error", "decryption failed" etc

## Options

The test file if you don't have target :

```bash
python test.py -m mysecretmessage
```

The exploit : 
```
usage: exploit.py [-h] -c CIPHER -l LENGTH_BLOCK_CIPHER --host HOST -u
                  URLTARGET --error ERROR [--cookie COOKIE]
                  [--method METHOD] [--post POST] [-v]
```
Details required options:
```bash
-h help
-c cipher chain
-l length of a block example: 8 or 16
-u UrlTarget for example: ?/page=
--host hostname example: google.fr
--error Error that the orcale give you for a wrong padding
    example: with HTTP method: 200,400,500
             with DOM HTML   : "<h2>Padding Error</h2>"
```
Optional options:
```bash
--cookie Cookie parameter example: PHPSESSID=9nnvje7p90b507shfmb94d7
--method Default GET methode but can se POST etc
--post POST parameter if you need example 'user':'value', 'pass':'value'
```

Example:
```bash
python exploit.py -c E3B3D1120F999F4CEF945BA8B9326D7C3C8A8B02178E59AF506666542AB5EF44 -l 16 --host host.com -u /index.aspx?c= -v --error "Padding Error"
```

<a href="https://asciinema.org/a/40222" target="_blank"><img src="https://asciinema.org/a/40222.png" height="350" width="550" ></a>

## Customisation

> I wan to customize the Oracle !

Example with sockets https://gist.github.com/mpgn/fce3c3f2aaa2eeb8fac5

No problem, find these line and do what you have to do :)

* Custom oracle response: 
```python
####################################
# CUSTOM YOUR RESPONSE ORACLE HERE #
####################################
''' the function you want change to adapte the result to your problem '''
def test_validity(response,error):
    try:
        value = int(error)
        if int(response.status) == value:
            return 1
    except ValueError:
        pass  # it was a string, not an int.

    # oracle repsonse with data in the DOM
    data = response.read()
    if data.find(error) == -1:
        return 1
    return 0
```

* Custom oracle call (HTTP)
```python
################################
# CUSTOM YOUR ORACLE HTTP HERE #
################################
def call_oracle(host,cookie,url,post,method,up_cipher):
    if post:
        params = urllib.urlencode({post})
    else:
        params = urllib.urlencode({})
    headers = {"Content-type": "application/x-www-form-urlencoded","Accept": "text/plain", 'Cookie': cookie}
    conn = httplib.HTTPConnection(host)
    conn.request(method, url + up_cipher, params, headers)
    response = conn.getresponse()
    return conn, response
```
