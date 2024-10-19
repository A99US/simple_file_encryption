Simple File Encryption. Written in C.

Only tested on Windows 7 32bit using Mingw32.

Passphrase and ad strings are limited to 1024 chars because using **fgets** in Windows need a fixed-length var. If you're on Linux you can use **getline** to get a dynamic mem-alloc var.

Still in development. There might be a breaking change in the future.

```
Simple File Encryption v1.0.0

Library      : Libsodium
KDF Algo     : Argon2 (ARGON2ID13)
Cipher Algo  : XChaCha20-Poly1305 (Stream Encryption)


Commands :

simplenc.exe <mode> <pass_file> <input_file> <output_file||null>

stdout | simplenc.exe <mode> <pass_file> "" <output_file||null>


- mode         : e -> To encrypt
                 d -> To decrypt
- pass_file    : File that contain passphrase, ad strings,
                 opslimit and memlimit. If it's not a file,
                 then it will be treated as the choosen passphrase.
- input_file   : File to process. If not provided / empty,
                 will process stdin instead.
- output_file  : File to save result to. If not provided / empty,
                 will output to terminal instead.


"pass_file" rules :

- 1st line is the passphrase. 1024 chars max. Can be empty.
- 2nd line is the ad strings. 1024 chars max. Can be empty.
- 3rd line is the opslimit. Default 3 on empty.
- 4th line is the memlimit. Default 134217728 on empty.


Warning :

- If "output_file" already exist, program will OVERWRITE it automatically.
  It will not ask for an overwrite confirmation.


Command Example :

simplenc.exe (No argument will default to show help)

simplenc.exe e "your unique passphrase" "data.txt" "data.txt.encrypted"

printf "Hello World" | simplenc.exe e "your unique passphrase" "" "message.enc"

tar -I "zstd -6" -c ".git" | simplenc.exe e "passfile.txt" > "gitRepo.enc"

simplenc.exe d "your unique passphrase" "message.enc" (output to terminal)

cat < "gitRepo.enc" | simplenc.exe d "passfile.txt" | tar -x --zstd
```

## License

[MIT](https://github.com/A99US/simple_file_encryption/blob/main/LICENSE)
