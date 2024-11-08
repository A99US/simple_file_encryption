
### Section
 - **[Introduction](#introduction)**
 - **[Compiling](#compiling)**
 - **[How To Use](#how-to-use)**
 - **[Header And Content Editing Without Decrypting](#header-and-content-editing-without-decrypting)**
 - **[License](#license)**

## Introduction

This is a Simple File Encryption program. Written in C.

Only tested on Windows 7 32bit using Mingw32.

Passphrase and ad strings are limited to 1024 chars because using **fgets** in Windows need a fixed-length var. If you're on Linux you can modify the code and use **getline** to use dynamic mem-alloc var and get a longer chars.

Still in development. There might be a breaking change in the future.

This version **v2.0.0** introduce a breaking change from previous version. Now you can attach a header to your encrypted file. Header could be a text or a binary. It could be from a files or strings that you set in the arg option. Header will also be encrypted.

You cannot decrypt file using **v2.0.0** if you encrypt it using **v.1.0.0** and vice versa.

## Compiling

```bash
# On Windows
gcc "simplenc.c" -o "simplenc.exe" -lsodium -municode -lws2_32
# On Linux / Mac
gcc "simplenc.c" -o "simplenc" -lsodium
```

## How To Use

```
Simple File Encryption v2.0.0 (2024102201)

Library      : Libsodium
KDF Algo     : Argon2 (ARGON2ID13)
Cipher Algo  : XChaCha20-Poly1305 (Stream Encryption)


Commands :

simplenc.exe <mode> <options> <input_file||null> <output_file||null>


- mode         : e     to encrypt file
                 d     to decrypt file's content
                 hd    to decrypt file's header
                 t     to decrypt without output (decryption test)
- options      : -pf   File, Passphrase file (more detail below)
                       If -pf is set, values from -p, -ops, -mem and
                       -ad will be ignored
                 -p    String, Passphrase
                       1024 chars max. Can be empty
                 -ops  Number, Argon2 Opslimit
                       Default 3 if not set / empty
                 -mem  Number, Argon2 Memlimit
                       Default 134217728 (128.00 MB) if not set / empty
                 -ad   String, Additional data for encryption
                       1024 chars max. Can be empty
                 -hd   File or String, For header content
                       Will be encrypted. Need to be decrypted to read
                       Could be a text file, or a binary file
                       If value is not a file, it will be the Header
                       ie. A file description, context, info, .exe, etc
                       Max length 524288 / 512.00 KB. Default empty
- input_file   : File to process. If not provided / empty,
                 will process stdin instead.
- output_file  : File to save result to. If not provided / empty,
                 will output to terminal instead.


"Passphrase file" rules :

- 1st line is the passphrase. 1024 chars max. Can be empty.
- 2nd line is the ad strings. 1024 chars max. Can be empty.
- 3rd line is the opslimit. Default 3 on empty.
- 4th line is the memlimit. Default 134217728 (128.00 MB) on empty.


Warning :

- If "output_file" already exist, program will OVERWRITE it automatically.
  It will not ask for an overwrite confirmation.


Command Example :

simplenc.exe (No argument will default to show help)

simplenc.exe e "data.txt" "data.txt.encrypted" (Encrypt with empty password)

simplenc.exe e -p "your unique passphrase" -hd "header.txt" "data.txt" "data.txt.encrypted"

printf "Hello World" | simplenc.exe e -p "your unique passphrase" -mem 250000000 "" "message.enc"

tar -I "zstd -6" -c ".git" | simplenc.exe e -hd "This is a backup repo v123" -pf "passfile.txt" > "gitRepo.enc"

simplenc.exe d -p "your unique passphrase" "message.enc" (output to terminal)

cat < "gitRepo.enc" | simplenc.exe d -pf "passfile.txt" | tar -x --zstd

simplenc.exe hd -p "your unique passphrase" "data.txt.encrypted" "header.txt"

cat < "gitRepo.enc" | simplenc.exe t -pf "passfile.txt"


Contribute improvement or report issues to <https://github.com/A99US/simple_file_encryption>.
```

## Header And Content Editing Without Decrypting

In the script **run.sh** there's a function **simpled()** that you can use to edit your encrypted file. The way it works is it will decrypt your file and save file's header and content to 2 different temporary files. Then they will be opened using nano. If at least one of them was edited and saved upon exiting nano, it will be re-encrypted. The original encrypted file will be renamed with **.[date].bkp** extension unless you choose not to backup.

Optionally, you can just update it with a file rather than editing in nano, using -hd and -f options.

Temp files will be shredded.

```
simpled <opt> encrypted_file

opt : -pf     Passfile
      -p      Passphrase
      -ops    Opslimit
      -mem    Memlimit
      -ad     Additional data
      -hd     New Header. File or string
      -f      New Content. File
      -nbu    No backup

# Editing header and content in nano
simpled -pf pass.txt file.enc

# Updating header from a file and editing content in nano
simpled -pf pass.txt -hd new_header.txt file.enc

# Updating header and content from files, no backup
simpled -pf pass.txt -hd new_header.txt -f data.csv -nbu file.enc
```

## License

**[MIT](https://github.com/A99US/simple_file_encryption/blob/main/LICENSE)**
