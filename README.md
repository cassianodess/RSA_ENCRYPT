# How to generate RSA public and private key pair in PKCS #8 format

1. Create key pair: `openssl genrsa -out private.pem 2048`
1. Extract public part: `openssl rsa -in private.pem -pubout -out public.pem`
1. Extract private part: `openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in private.pem -out pkcs8.pem`
