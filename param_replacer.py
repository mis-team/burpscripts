#This script encodes http header and/or parameter according porcessHeader and processParam functions
#Ex: if you wand to FUZZ with burp ActiveScan username in basic authorization header, and/or some part of base64-encoded cookie
# you have to simple deBase64 it in repeater, set FUZZ points (in intruder or via manual insertion point extension) 
# and set headername/paramname values in script. Then run Active scan as usual...
# Parameters will be encoded by script
# You can control that script works correct via Logger++ extension
# paramtype is a plase for encoded param in output request


headername = "Authorization"
paramname = "session"
paramtype = 2 #0 - get, 1 - post, 2 - cookie

def processHeader(header):
    import base64
    return "Basic " + base64.b64encode(header)

def processParam(param):
    import base64
    return base64.b64encode(param)

if toolFlag in (callbacks.TOOL_REPEATER, callbacks.TOOL_SCANNER, callbacks.TOOL_EXTENDER ):
    # only apply to requests
    if messageIsRequest:
        
        # remove any existing Authorization header
        request = helpers.analyzeRequest(messageInfo)
        headers = request.getHeaders()
        for header in headers:
            if header.startswith(headername):
                headers.remove(header)
                headervalue = header.split(': ')[1]
                headers.add('{}: {}'.format(headername, processHeader(headervalue)))
                #print "Header replaced"
                break

        body = messageInfo.getRequest()[request.getBodyOffset():]
        new_request = helpers.buildHttpMessage(headers, body)

        origparam = helpers.getRequestParameter(new_request,paramname)
        if origparam:
            #print "Found param: " + str(origparam)
            newparam = helpers.buildParameter(paramname,processParam(origparam.getValue()),paramtype)
            new_request = helpers.updateParameter(new_request,newparam)
            #print "Parameter replaces"
            
        messageInfo.setRequest(new_request)

