# EzSSL
A ruby extension to make secure TCPSocket connections

## Why am I making this?
I have personally had a lot of problems trying to use the `OpenSSL` and `Socket` libraries together to make a secure connection. Too many hours have gone into researching the openssl doccumentation to just get the basic idea of what i need to do.

I would get padding errors. I tried using the `OpenSSL::SSL::SSLSocket` object just to get more confused.

It eventually got to the point where i thought it would be easier to make my own encryption method, which worked, but was insecure.

Now that I have returned to using the `openssl` library, and I have learned the ins and outs, I wish to make the process easier, and to make the process easier for people new to socket programming.
