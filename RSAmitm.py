
privkeyb64="MIIEowIBAAKCAQEAq/IPTua6isZT3BC+OSHDzjUP1qAmPBcLCLL0H2s96lie00IFcTcU+6IDhsKL1MkfIqCCnlHG6IUOZWSudKRy7B3nYSCuRvk7r/n5+4J+eZt4GUBtU/vdj47jQUJYwIpO66s/P/O1Q+HlRdEjLveNqX1pvN9DaTtLmbMTBRZgiirJMNmhB3XvCR/ikRDjWyNAcA5O7IiJajDVu2lQrZDrevV2UnG1nkcA3bUcHYcx3BUhHI81dwc63u7vzCOefWmHmQM97Ugx7zs0FcQ/meZQd+w+xorUXn6UualXLxOZ1nh3aoV0LbJN3iBqTLfCdnUngyZpsXi8ZT2ffA7Ch27SowIDAQABAoIBAE0BqLd2gB78ubv6R6dApvfoLcK6kMUisM9hjhGwLteQfvkwPU26FIypv5iP8p4GwQn6BuWuzD2AsbTZRYR5zfpPXjvSrhqdLo0ekEWC6O+/oCb3Ar+1MkJEBSVJ+IOqrbPASyByHkFbnxoIkxBK0EgTIdLzzrYHV1FrsN37apsV2FWDR9XpWNX6ixzPJhfAJquFt+eFMMZvOzD7AVkla6ZrUrcJoPr+bERIdcpTV1J7Fa2/Ja+lhOqW9VPL9teqVOqS1V88uFH6ZxwL7GlEuwUmYcxW9LhGmcyGjDHXjimNtVcTmwu4hmsKqE+9fY2sFXmLFZ9K8oVbcplKJsd4uOECgYEA2pUh9mmBWMsJDy4Bl2hLqi3C2wm6m67hiXCxf0U8QxZmq2hBuXwdQ0POoHEd9HMxuz7Eml84U7B3jWomqH0zb48b3OEi2lNc9RNJRcMqaETeXIGUKFFmZFZv64zNooCB25Gvzq75bbf/Cl046OYJMgvn+SLZfJ/FrV+tF510Y/MCgYEAyWErfeo8kmklftCvPe7lzNgeQpq+BGCXi7dvsVgVZhSn1RcaU/VxFaBZKNnefjl/fFynm/wEoDNlN5GJvMvcN5ZJczBKA3GqKos9yXb9vQJP5H71WsKJLp/ougzXU8nK+TNenbHWQkRIH6RdokPfKHMCQ9hB0gl3NqaZ/mwAcpECgYBUh1ea8zISJHJcbG4xHyQjq46vJhQEIJ0XiX0auquTRhZuMuM318d5O7+sTBJJdkLFJoDhMfGWa6fQCDzq63/4pF8iC+5uf85y+AJd+BtuNzPGklW5QcFXDBY8ATeEoC2Xu79BLmlHBOCcIXDgoBTuRaxvrApvJ1pKsbU+bKWWAQKBgQCLpQxJxpK2XJ+ZrxC2e+FzCTMCsNevpWOxiUS00AYWwaAYjmq9aeg/PPBW+a3mDe0vyfiYnEyA4uL/g7bl6uAM0/SfIg9REBMWaXQxLoiJ9v57zuZJR7llUZJK4fi3q6lK4aps5BNV5I+3EX20tigbnpUlguMxyUqX5TPIUBCHYQKBgCshcuIBDrF2Bc3Vr0kwAMhkrQIJlGp/UKWSZCfgGgrvpp7i3odaM1DORsBpksdn3WA8Wrd2zyUNok8C6TMwraHqTSXn5ZVx48vbMe5QBWm3DemJu/FTrlHfwoJ8XBFLAfrz5gVmnmcQemAWvOzbx6Sg3atae3wq305u7bpEBUZK"

pubkeybase64="MIIBCgKCAQEAq/IPTua6isZT3BC+OSHDzjUP1qAmPBcLCLL0H2s96lie00IFcTcU+6IDhsKL1MkfIqCCnlHG6IUOZWSudKRy7B3nYSCuRvk7r/n5+4J+eZt4GUBtU/vdj47jQUJYwIpO66s/P/O1Q+HlRdEjLveNqX1pvN9DaTtLmbMTBRZgiirJMNmhB3XvCR/ikRDjWyNAcA5O7IiJajDVu2lQrZDrevV2UnG1nkcA3bUcHYcx3BUhHI81dwc63u7vzCOefWmHmQM97Ugx7zs0FcQ/meZQd+w+xorUXn6UualXLxOZ1nh3aoV0LbJN3iBqTLfCdnUngyZpsXi8ZT2ffA7Ch27SowIDAQAB"

pubkeyserverb64=""


#from pyscripterer import BaseScript as Script

if toolFlag in (callbacks.TOOL_REPEATER, callbacks.TOOL_SCANNER, callbacks.TOOL_EXTENDER, callbacks.TOOL_PROXY ):
    # only apply to requests
    if not messageIsRequest:
        #print "message is response"
        import re
        import base64

        response = helpers.bytesToString(messageInfo.getResponse())
        match = re.search(r'MIIB.*DAQAB', response, re.DOTALL)

        if match:
            print "Got match !! Replacing pub key"
            pubkeyserverb64 = match.group(0)
            callbacks.saveExtensionSetting("RSA_ServerPublicKeySave", pubkeyserverb64)
            newresponse = response.replace(pubkeyserverb64,"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A"+pubkeybase64)
            messageInfo.setResponse(newresponse)

    if messageIsRequest:
        #print "message is request"
        import re
        import base64

        request = helpers.bytesToString(messageInfo.getRequest())
        match = re.search(r'encryptedKey".*"transformation"', request, re.DOTALL)
        if match:
            print "got match resigning symmetric key"
            pubkeyserverb64 = callbacks.loadExtensionSetting("RSA_ServerPublicKeySave")
            pubkeyserverb64 = pubkeyserverb64.replace("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A","")

            encMessage = helpers.getRequestParameter(request, "encryptedKey")
            if encMessage:
                import rsa
                import binascii
                privkey = rsa.PrivateKey.load_pkcs1("-----BEGIN RSA PRIVATE KEY-----\n"+privkeyb64+"\n-----END RSA PRIVATE KEY-----","PEM")
                pubkey = rsa.PublicKey.load_pkcs1("-----BEGIN RSA PUBLIC KEY-----\n"+pubkeyserverb64+"\n-----END RSA PUBLIC KEY-----","PEM")
                #pubkey = rsa.PublicKey.load_pkcs1(pubkeyserverb64,"PEM")
                decMessage = rsa.decrypt(base64.b64decode(encMessage.getValue()), privkey)
                print "Symmetric key:"
                print(binascii.hexlify(decMessage))
                print(base64.b64encode(decMessage))
                encMessage = rsa.encrypt(decMessage,pubkey)

                newrequest = request.replace(match.group(0),'encryptedKey":"'+base64.b64encode(encMessage)+'","transformation"')

                #burp api hack to update Content-Length...
                tmpparam = helpers.buildParameter("bbbtest","1",0)
                newrequest = helpers.updateParameter(newrequest,tmpparam)
                newrequest = helpers.removeParameter(newrequest,tmpparam)
            
                #print newrequest.tostring()
                messageInfo.setRequest(newrequest)
