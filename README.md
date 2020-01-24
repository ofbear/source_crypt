# source_crypt
## ready
### lib
$ dnf install -y gcc openssl openssl-*

### compile
$ gcc -o source_crypt.exe source_crypt.c -lcrypto

## how to make
arg[1] mode encrypt
            decrypt
arg[2] target path
arg[3] output path
