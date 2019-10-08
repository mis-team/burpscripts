# burpscripts
Scripts for burp scripter

This scrits are used to modify burp suite outgoing requests with Burp python scripter extension.

For example: if you havea cookie:
   _csrf=someprefix%3aTzoxODoiUEhQIjoxOntzOjY6ImluamVjdCI7czoxNzoic3lzdGVtKCcvdXNyL2Jpbi9zbGVlcCAxMCcpOyI7%3asomesuffix
   
   (after decoding: _csrf=someprefix:O:18:"PHP":1:{s:6:"inject";s:17:"system('/usr/bin/sleep 10');";:somesuffix) 
   
and you want to fuzz some fields inside it...

You may use this cookie in cleartext in repeater and set FUZZ "brackets":

  _csrf=someprefix%3aFUZZO:18:"PHP":1:{s:6:"inject";s:17:"system('/usr/bin/sleep 10');";FUZZ%3asomesuffix
  
So all inside FUZZ "brackets" will be encoded or based (accourding processParam function)

The other useful scripts you may to view in lanmaster53 gist: https://gist.github.com/lanmaster53/3d868369d0ba5144b215921d4e11b052
