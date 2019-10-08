# This script encodes string inside FUZZ (FUZ2Z) "brackets" according processParam (processParam2) functions
# Ex: if you wand to fuzzing with burp ActiveScan username in basic authorization header, and/or some part of some-encoded cookie
# Example: Cookie: foo=bar; _csrf=someprefix:O%3a18%3a"PHP"%3a1%3a{s%3a6%3a"inject"%3bs%3a17%3a"system('/usr/bin/sleep+10')%3b"%3b}
# you have to type it in cleartext in repeater, set "FUZZ" brackets and set fuzzing points (in intruder or via manual insertion point extension) 
# Example: Cookie: foo=bar; _csrf=someprefixFUZZ:O:18:"PHP":1:{s:6:"inject";s:17:"system('/usr/bin/sleep 10');";}FUZZ
# Then run Active scan as usual...
# All string inside FUZZ brackets will be encoded by script.
# Additionaly you can set alternate FUZ2Z brackets (as in wfuzz)...
# To control script works - You can use Logger++ extension

import re

def processParam(param, helpers):
    return str(helpers.urlEncode(param))

def processParam2(param, helpers):
    import base64
    return base64.b64encode(param)



if toolFlag in (callbacks.TOOL_REPEATER, callbacks.TOOL_SCANNER, callbacks.TOOL_EXTENDER ):
    # only apply to requests
    if messageIsRequest:
        request = messageInfo.getRequest()

        #sfvrvgr
        if len(re.findall(r'FUZZ.*FUZZ',request))>0:
            print "Found FUZZ point"
            param = re.findall(r'FUZZ.*FUZZ',request)[0]
            param = param.replace('FUZZ','')
            newparam = processParam(param, helpers)
            newrequest = re.sub(r'FUZZ.*FUZZ',newparam,request)
        else:
            print "FUZZ point not found"
            newrequest = request

        if len(re.findall(r'FUZ2Z.*FUZ2Z',request))>0:
            #print "Found FUZ2Z"
            param = re.findall(r'FUZ2Z.*FUZ2Z',request)[0]
            param = param.replace('FUZ2Z','')
            newparam = processParam2(param, helpers)
            newrequest = re.sub(r'FUZ2Z.*FUZ2Z',newparam,newrequest)


        #burp api hack to update Content-Length...
        tmpparam = helpers.buildParameter("bbbtest","1",0)
        newrequest = helpers.updateParameter(newrequest,tmpparam)
        newrequest = helpers.removeParameter(newrequest,tmpparam)
        
        messageInfo.setRequest(newrequest)


