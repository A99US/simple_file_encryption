#include <sodium.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <locale.h>
#include <sys/time.h>

// #if defined(_WIN32) || defined(_WIN64)
// _WIN32 for both 32 and 64
// _WIN64 specifically for 64
#ifdef _WIN32
  #include <winsock2.h> // For htonl & ntohl on Windows
  #include <windows.h>
  #include <wchar.h>
  #include <fcntl.h>
  #include <io.h>
  #define PLTFRM "WIN"
  #define LCLOPT "id_ID" //"Indonesian_Indonesia.1252" //"id_ID.utf8" //
#else
  #include <arpa/inet.h> // For htonl & ntohl on Linux
  #define PLTFRM "NIX"
  #define LCLOPT "id_ID.UTF-8"
#endif

#define SIG_STRING "SIMPL"
#define SIG_V_TAG "v2.0.0"
#define SIG_V_NUMBER 2024102201
#define REPO_URL "https://github.com/A99US/simple_file_encryption"
#define SALT_SIZE crypto_pwhash_argon2id_SALTBYTES                // 16
#define KEY_SIZE crypto_secretstream_xchacha20poly1305_KEYBYTES   // 32
#define TAG_SIZE crypto_secretstream_xchacha20poly1305_ABYTES     // 16
#define HEADER_SIZE crypto_secretstream_xchacha20poly1305_HEADERBYTES
#define OPSLIMIT 3 // crypto_pwhash_OPSLIMIT_MODERATE
#define MEMLIMIT 134217728 // 16384 // crypto_pwhash_MEMLIMIT_MODERATE
// buffer chunk size to read input
// 524288 is the sweet spot performance for my particular machine
// 33554432 16777216 8388608 4194304 2097152 1048576 524288 262144 65536 4096
#define BUFFER_CHUNK 524288
// Size limit for password and ad char length
// 1024 chars + 1 null
// Just because I need a fixed length var
// Windows limitation of using fgets
// POSIX getline would be dynamic
#define ARGON2_STRING_LIMIT 1025

/*
TODO LIST :
- byte2wide and wide2byte change arg value and return retCode instead of result directly.
*/

// ========================== NUM TO BYTE CONVERTER ===========================
char *num2byte ( const double bytes, int precision ) {
  const char *units[] = { "Bytes", "KB", "MB", "GB", "TB" };
  double numPrint = bytes;
  int index = 0;
  while (numPrint >= 1024 && index < 4) {
    numPrint /= 1024;
    index++;
  }
  char *result = (char *)malloc(15);
  sprintf(result, "%.*f %s", precision, numPrint, units[index]);
  return result;
}
#ifdef _WIN32
// =========================== MULTIBYE TO WIDECHAR ===========================
wchar_t *byte2wide(const char *mb_str){
  long wc_len = MultiByteToWideChar(CP_UTF8, 0, mb_str, -1, NULL, 0);
  if (wc_len <= 0) {
    fprintf(stderr, "Error calculating length : %ld\n", GetLastError());
    exit(-1);
  }
  wchar_t *wc_str = (wchar_t *)malloc(wc_len * sizeof(wchar_t));
  MultiByteToWideChar(CP_UTF8, 0, mb_str, -1, wc_str, wc_len);
  return wc_str;
}
// =========================== WIDECHAR TO MULTIBYE ===========================
char *wide2byte(const wchar_t *wc_str) {
  long mb_len = WideCharToMultiByte(CP_UTF8, 0, wc_str, -1, NULL, 0, NULL, NULL);
  if (mb_len <= 0) {
    fprintf(stderr, "Error calculating length : %ld\n", GetLastError());
    exit(-1);
  }
  char *mb_str = malloc(mb_len);
  WideCharToMultiByte(CP_UTF8, 0, wc_str, -1, mb_str, mb_len, NULL, NULL);
  return mb_str;
}
#endif
// ================================== STRTOL ==================================
static int str2l ( long *num, const char *line, const char *text ) {
  char *endptr;
  *num = strtol(line, &endptr, 10);
  if (strcmp(line,endptr) == 0) {
    fprintf(stderr, "%sDoesn't Contain Any Digit! (%s)\n", text, line);
    return -1;
  }
  else if (*endptr != '\0') {
    fprintf(stderr, "%sContain Non-Numeric Char! (%s)\n", text, line);
    return -1;
  }
  else if ((*num == LONG_MAX || *num == LONG_MIN) && errno == ERANGE) {
    fprintf(stderr, "%sNumber Is Out of Range! (%s)\n", text, line);
    return -1;
  }
  return 0;
}
// ============================== REMOVE NEWLINE ==============================
void line_sanitizer(char *line) {
  line[strcspn(line, "\r")] = 0;  // Windows files
  line[strcspn(line, "\n")] = 0;  // Unix files
  line[strlen(line)] = '\0';      // Null terminated
}
// =========================== ARGON2 KEY GENERATOR ===========================
static int argon2key(unsigned char *key, const char *passVal, const unsigned char *salt, const long *opsl, const long *meml) {
  struct timeval start, end;
  gettimeofday(&start, NULL);
  fprintf(stderr, "Making Argon2 Key . . . ");
  if (crypto_pwhash(key, KEY_SIZE, passVal, strlen(passVal), salt, *opsl, *meml, crypto_pwhash_ALG_ARGON2ID13) != 0) {
    fprintf(stderr, "\n\nKey derivation failed!\n");
    return -1;
  }
  gettimeofday(&end, NULL);
  double duration = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) / 1000000.0;
  fprintf(stderr, "completed in %.2f second%s\n\n", duration, duration>1?"s":"");
  return 0;
}
// ============================= PASSFILE FETCHER =============================
static int pass_file_fetcher(const char *input_pass, const char *pass_arg, const char *ad_arg, char *pass, char *ad, long *ops, long *mem) {
  if (*input_pass != '\0') {
    int retCode = -1;
    FILE *passFile = NULL;
    passFile = strcmp(PLTFRM,"WIN") == 0 ?
               _wfopen((wchar_t *)byte2wide(input_pass), L"rb") :
               fopen(input_pass, "rb");
    if (!passFile) {
      fprintf(stderr, "PassFile doesn't exist!\n");
      return -1;
    }
    fseek(passFile, 0, SEEK_END);
    long pass_size = ftell(passFile);
    fseek(passFile, 0, SEEK_SET);
    size_t line_limit = ARGON2_STRING_LIMIT + 5;
    char line[line_limit];
    int id = 0;
    if (pass_size <= 0) {
      goto retPoint0;
    }
    while (fgets(line, line_limit, passFile) != NULL && id < 4) {
      line_sanitizer(line);
      size_t lineLn = strlen(line);
      char *idString = id == 0 ? "Passphrase" : "Ad";
      if (id < 2 && lineLn >= ARGON2_STRING_LIMIT) {
        fprintf(stderr,"%s Strings is longer than %d chars!\n", idString, (ARGON2_STRING_LIMIT-1));
        goto retPoint1;
      }
      //fprintf(stderr,"%d. \"%s\" : \"%d\"\n", id, line, lineLn); //exit(0);
      if (id == 0) {
        strncpy(pass,line,lineLn); pass[lineLn] = '\0';
      }
      if (id == 1) {
        strncpy(ad,line,lineLn); ad[lineLn] = '\0';
      }
      else if (id == 2 && lineLn > 0 && str2l(&*ops, line, "Opslimit ") != 0) {
        goto retPoint1;
      }
      else if (id == 3 && lineLn > 0 && str2l(&*mem, line, "Memlimit ") != 0) {
        goto retPoint1;
      }
      id++;
    }
retPoint0:
    retCode = 0;
retPoint1:
    sodium_memzero(line, sizeof line);
    fclose(passFile);
    return retCode;
  }
  else {
    if (strlen(pass_arg) >= ARGON2_STRING_LIMIT) {
      fprintf(stderr, "Passphrase Strings is longer than %d chars!\n", ARGON2_STRING_LIMIT-1);
      return -1;
    }
    if (strlen(ad_arg) >= ARGON2_STRING_LIMIT) {
      fprintf(stderr, "Ad Strings is longer than %d chars!\n", ARGON2_STRING_LIMIT-1);
      return -1;
    }
    strncpy(pass,pass_arg,strlen(pass_arg));
    pass[strlen(pass_arg)] = '\0';
    strncpy(ad,ad_arg,strlen(ad_arg));
    ad[strlen(ad_arg)] = '\0';
    return 0;
  }
}
// =========================== ENCRYPTION FUNCTION ============================
static int encrypt_file ( const char *input_file, const char *output_file, const char *passfile, const char *headerfile, const char *password, long *opsVal, long *memVal, const char *ad ) {
  int retCode = -1;
  // Vars for Argon2
  unsigned char key[KEY_SIZE];
  unsigned char salt[SALT_SIZE];
  randombytes_buf(salt, SALT_SIZE);
  char passVal[ARGON2_STRING_LIMIT] = "";
  char adVal[ARGON2_STRING_LIMIT] = "";
  //long opsVal = OPSLIMIT;
  //long memVal = MEMLIMIT;
  // Vars for SecretStream
  unsigned char buf_in[BUFFER_CHUNK] = "";
  unsigned char buf_out[BUFFER_CHUNK + TAG_SIZE];
  unsigned char header[HEADER_SIZE];
  crypto_secretstream_xchacha20poly1305_state st;
  unsigned long long out_len;
  size_t rlen = 0;
  int eof;
  unsigned char tag = 0;
  double total_read = 0;
  // Vars for Files
  FILE *data_input = NULL, *data_output = NULL;
  data_input = strcmp(input_file,"") == 0 ? stdin :
               strcmp(PLTFRM,"WIN") == 0 ?
               _wfopen((wchar_t *)byte2wide(input_file), L"rb") :
               fopen(input_file, "rb");
  data_output = strcmp(output_file,"") == 0 ? stdout :
                strcmp(PLTFRM,"WIN") == 0 ?
                _wfopen((wchar_t *)byte2wide(output_file), L"wb") :
                fopen(output_file, "wb");
  if (data_input == NULL) {
    fprintf(stderr, "Input file doesn't exist!\n");
    return -1;
  }
  if (*headerfile != '\0') {
    FILE *header_input = strcmp(PLTFRM,"WIN") == 0 ?
          _wfopen((wchar_t *)byte2wide(headerfile), L"rb") :
          fopen(headerfile, "rb");
    // File doesn't exist
    if (!header_input) {
      if (strlen(headerfile) >= BUFFER_CHUNK) {
        fprintf(stderr, "Header Strings exceed the size limit of %d / %s!\n", BUFFER_CHUNK, num2byte(BUFFER_CHUNK,2));
        return -1;
      }
      strncpy((char *)buf_in,headerfile,strlen(headerfile));
      buf_in[strlen(headerfile)] = '\0';
      rlen = strlen(headerfile);
    }
    // File exist
    else {
      rlen = fread(buf_in, 1, BUFFER_CHUNK, header_input);
      eof = feof(header_input);
      fclose(header_input);
      if (!eof) {
        fprintf(stderr, "Header File exceed the size limit of %d / %s!\n", BUFFER_CHUNK, num2byte(BUFFER_CHUNK,2));
        return -1;
      }
    }
  }
  if (pass_file_fetcher(passfile,password,ad,passVal,adVal,&*opsVal,&*memVal) != 0) {
    goto retPoint1;
  }
  if (argon2key(key, passVal, salt, &*opsVal, &*memVal) != 0) {
    goto retPoint2;
  }
  //fprintf(stderr,"\n\"%s\" \"%s\" \"%s\" \"%s\" \"%ld\" \"%ld\"\n\n", input_file, output_file, passVal, adVal, opsVal, memVal); //exit(0);
  // Add SIGNATURE
  fwrite(SIG_STRING, 1, 5, data_output);
  // Add VERSION NUMBER
  uint32_t SIG_NUMBER = htonl(SIG_V_NUMBER);
  fwrite(&SIG_NUMBER, 1, sizeof(SIG_NUMBER), data_output);
  fwrite(salt, 1, SALT_SIZE, data_output);
  if (crypto_secretstream_xchacha20poly1305_init_push(&st, header, key) != 0) {
    fprintf(stderr, "Failed to create stream header!\n");
    goto retPoint3;
  }
  fwrite(header, 1, sizeof header, data_output);
  // Encrypting header, even if it's empty
  if (crypto_secretstream_xchacha20poly1305_push(&st, buf_out, &out_len, buf_in, rlen, (unsigned char*)adVal, strlen(adVal), tag) != 0) {
    fprintf(stderr, "Failed to encrypt header!\n");
    goto retPoint4;
  }
  total_read += rlen;
  uint32_t header_len = htonl(out_len);
  fwrite(&header_len, 1, sizeof(header_len), data_output);
  fwrite(buf_out, 1, (size_t) out_len, data_output);
  fprintf(stderr, "Header Length : %d\n\n", rlen);
  struct timeval start, end;
  double duration;
  gettimeofday(&start, NULL);
  do {
    rlen = fread(buf_in, 1, BUFFER_CHUNK, data_input);
    total_read += rlen;
    eof = feof(data_input);
    tag = eof ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0;
    if (crypto_secretstream_xchacha20poly1305_push(&st, buf_out, &out_len, buf_in, rlen, (unsigned char*)adVal, strlen(adVal), tag) != 0) {
      fprintf(stderr, "Failed to encrypt!\n");
      goto retPoint4;
    }
    fwrite(buf_out, 1, (size_t) out_len, data_output);
    gettimeofday(&end, NULL);
    duration = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) / 1000000.0;
    fprintf(
      stderr,
      "\rTotal Bytes Encrypted : %s  (%s/s)      ",
      num2byte(total_read,2),
      num2byte(total_read/(duration<1?1:duration),1)
    );
  } while (! eof);
  gettimeofday(&end, NULL);
  duration = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) / 1000000.0;
  fprintf(stderr, "\n\nEncryption completed in %.2f second%s\n", duration, duration>=2?"s":"");
  retCode = 0;
retPoint4:
  sodium_memzero(buf_in, rlen);
  sodium_memzero(buf_out, out_len);
retPoint3:
  sodium_memzero(header, HEADER_SIZE);
retPoint2:
  sodium_memzero(key, KEY_SIZE);
retPoint1:
  fclose(data_input);
  fclose(data_output);
  return retCode;
}

// =========================== DECRYPTION FUNCTION ============================
static int decrypt_file ( const char *input_file, const char *output_file, const char *passfile, const char *headerfile, const char *password, long *opsVal, long *memVal, const char *ad, const char *mode ) {
  int test = strcmp(mode,"t");
  int retCode = -1;
  // Vars for Argon2
  unsigned char key[KEY_SIZE];
  unsigned char salt[SALT_SIZE];
  char passVal[ARGON2_STRING_LIMIT] = "";
  char adVal[ARGON2_STRING_LIMIT] = "";
  //long opsVal = OPSLIMIT;
  //long memVal = MEMLIMIT;
  // Vars for SecretStream
  unsigned char buf_in[BUFFER_CHUNK + TAG_SIZE];
  unsigned char buf_out[BUFFER_CHUNK];
  unsigned char header[HEADER_SIZE];
  crypto_secretstream_xchacha20poly1305_state st;
  unsigned long long out_len;
  size_t rlen;
  int eof;
  unsigned char tag = 0;
  double total_read = 0;
  // Vars for Files
  FILE *data_input = NULL, *data_output = NULL;
  data_input = strcmp(input_file,"") == 0 ? stdin :
               strcmp(PLTFRM,"WIN") == 0 ?
               _wfopen((wchar_t *)byte2wide(input_file), L"rb") :
               fopen(input_file, "rb");
  data_output = strcmp(output_file,"") == 0 ? stdout :
                strcmp(PLTFRM,"WIN") == 0 ?
                _wfopen((wchar_t *)byte2wide(output_file), L"wb") :
                fopen(output_file, "wb");
  if (data_input == NULL) {
    fprintf(stderr, "Input file doesn't exist!\n");
    return -1;
  }
  // Read SIGNATURE
  fread(buf_in, 1, 5, data_input);
  if (strcmp((char *)buf_in, SIG_STRING) != 0) {
    fprintf(stderr, "Input file is not an encrypted file. No Signature Found!\n");
    goto retPoint1;
  }
  // Read VERSION NUMBER
  uint32_t SIG_NUMBER;
  fread(&SIG_NUMBER, 1, sizeof(SIG_NUMBER), data_input);
  SIG_NUMBER = ntohl(SIG_NUMBER);
  if (SIG_NUMBER != SIG_V_NUMBER) {
    fprintf(stderr,
      "Can't decrypt your Input file.\n"
      "File was encrypted using Version '%d'.\n"
      "This program version is '%d'.\n"
      "Go to GitHub repo and download the right version.\n\n<%s>\n"
      ,
      SIG_NUMBER, SIG_V_NUMBER, REPO_URL
    );
    goto retPoint1;
  }
  if (pass_file_fetcher(passfile,password,ad,passVal,adVal,&*opsVal,&*memVal) != 0) {
    goto retPoint1;
  }
  fread(salt, 1, SALT_SIZE, data_input);
  if (argon2key(key, passVal, salt, &*opsVal, &*memVal) != 0) {
    goto retPoint2;
  }
  //fprintf(stderr,"\n\"%s\" \"%s\" \"%s\" \"%s\" \"%ld\" \"%ld\"\n", input_file, output_file, passVal, adVal, opsVal, memVal); //exit(0);
  fread(header, 1, HEADER_SIZE, data_input);
  if (crypto_secretstream_xchacha20poly1305_init_pull(&st, header, key) != 0) {
    /* incomplete header */
    fprintf(stderr, "Corrupted stream header!\n");
    goto retPoint3;
  }
  // Decrypting Header
  uint32_t header_len;
  fread(&header_len, 1, sizeof(header_len), data_input);
  header_len = ntohl(header_len);
  rlen = fread(buf_in, 1, header_len, data_input);
  if (crypto_secretstream_xchacha20poly1305_pull(&st, buf_out, &out_len, &tag, buf_in, rlen, (unsigned char*)adVal, strlen(adVal)) != 0) {
    /* corrupted chunk */
    fprintf(stderr, "%sDecryption failed!\n", strcmp(mode,"hd") == 0?"Header ":"");
    goto retPoint4;
  }
  fprintf(stderr, "Header Length : %lld\n\n", out_len);
  // Mode 'hd' : Only stdout Header
  if (strcmp(mode,"hd") == 0) {
    fprintf(stderr, "Header Decryption completed.\n");
    if (strcmp(output_file,"") == 0) {
      fprintf(
        stderr,
        "\n"
        "--------------------------- HEADER CONTENT ---------------------------"
        "\n\n"
      );
    }
    fwrite(buf_out, 1, (size_t) out_len, data_output);
    goto retPoint5;
  }
  struct timeval start, end;
  double duration;
  gettimeofday(&start, NULL);
  do {
    rlen = fread(buf_in, 1, sizeof buf_in, data_input);
    total_read += rlen;
    eof = feof(data_input);
    if (crypto_secretstream_xchacha20poly1305_pull(&st, buf_out, &out_len, &tag, buf_in, rlen, (unsigned char*)adVal, strlen(adVal)) != 0) {
      /* corrupted chunk */
      fprintf(stderr, "Decryption failed!\n");
      goto retPoint4;
    }
    if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
      if (! eof) {
        /* end of stream reached before the end of the file */
        fprintf(stderr, "\nEnd of stream but not end of file!\n");
        goto retPoint4;
      }
    } else { /* not the final chunk yet */
      if (eof) {
        /* end of file reached before the end of the stream */
        fprintf(stderr, "\nEnd of file but not end of stream!\n");
        goto retPoint4;
      }
    }
    if (test != 0) {
      fwrite(buf_out, 1, (size_t) out_len, data_output);
    }
    gettimeofday(&end, NULL);
    duration = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) / 1000000.0;
    fprintf(
      stderr,
      "\rTotal Bytes Decrypted : %s  (%s/s)      ",
      num2byte(total_read,2),
      num2byte(total_read/(duration<1?1:duration),1)
    );
  } while (! eof);
  gettimeofday(&end, NULL);
  duration = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) / 1000000.0;
  fprintf(stderr, "\n\nDecryption%s completed in %.2f second%s\n", test==0?" Test":"", duration, duration>=2?"s":"");
  // Mode 'hd' : stdout Decryption
  if (strcmp(mode,"d") == 0 && strcmp(output_file,"") == 0) {
    fprintf(
      stderr,
      "\n"
      "---------------------------- FILE CONTENT ----------------------------"
      "\n\n"
    );
    //fwrite(buf_out, 1, (size_t) out_len, data_output);
    //goto retPoint5;
  }
  // Mode 't' : Test Decryption
  if (strcmp(mode,"t") == 0) {
    fprintf(stderr, "\nIt is a valid Encrypted File!\n\n");
  }
retPoint5:
  retCode = 0;
retPoint4:
  sodium_memzero(buf_in, rlen);
  sodium_memzero(buf_out, out_len);
retPoint3:
  sodium_memzero(header, HEADER_SIZE);
retPoint2:
  sodium_memzero(key, KEY_SIZE);
retPoint1:
  fclose(data_input);
  fclose(data_output);
  return retCode;
}
// =============================== PRINT HELPER ===============================
void helper ( char *appPath ) {
  char *appName = strrchr(appPath, '\\');
  size_t strLength = ARGON2_STRING_LIMIT - 1;
  if (appName == NULL) {
    appName = strrchr(appPath, '/');
  }
  if (appName != NULL) {
    appName++;
  }
  else {
    appName = appPath;
  }
  printf(
    "\nSimple File Encryption %s (%d)\n\n"
    "Library      : Libsodium\n"
    "KDF Algo     : Argon2 (ARGON2ID13)\n"
    "Cipher Algo  : XChaCha20-Poly1305 (Stream Encryption)\n\n\n"
    "Commands : \n\n"
    "%s <mode> <options> <input_file||null> <output_file||null>\n\n\n"
    "- mode         : e     to encrypt file\n"
    "                 d     to decrypt file's content\n"
    "                 hd    to decrypt file's header\n"
    "                 t     to decrypt without output (decryption test)\n"
    "- options      : -pf   File, Passphrase file (more detail below)\n"
    "                       If -pf is set, values from -p, -ops, -mem and\n"
    "                       -ad will be ignored\n"
    "                 -p    String, Passphrase\n"
    "                       %d chars max. Can be empty\n"
    "                 -ops  Number, Argon2 Opslimit\n"
    "                       Default %d if not set / empty\n"
    "                 -mem  Number, Argon2 Memlimit\n"
    "                       Default %d (%s) if not set / empty\n"
    "                 -ad   String, Additional data for encryption\n"
    "                       %d chars max. Can be empty\n"
    "                 -hd   File or String, For header content\n"
    "                       Will be encrypted. Need to be decrypted to read\n"
    "                       Could be a text file, or a binary file\n"
    "                       If value is not a file, it will be the Header\n"
    "                       ie. A file description, context, info, .exe, etc\n"
    "                       Max length %d / %s. Default empty\n"
    "- input_file   : File to process. If not provided / empty,\n"
    "                 will process stdin instead.\n"
    "- output_file  : File to save result to. If not provided / empty,\n"
    "                 will output to terminal instead.\n\n\n"
    "\"Passphrase file\" rules :\n\n"
    "- 1st line is the passphrase. %d chars max. Can be empty.\n"
    "- 2nd line is the ad strings. %d chars max. Can be empty.\n"
    "- 3rd line is the opslimit. Default 3 on empty.\n"
    "- 4th line is the memlimit. Default %d (%s) on empty.\n\n\n"
    "Warning : \n\n"
    "- If \"output_file\" already exist, program will OVERWRITE it automatically.\n"
    "  It will not ask for an overwrite confirmation.\n\n\n"
    "Command Example :\n\n"
    "%s (No argument will default to show help)\n\n"
    "%s e \"data.txt\" \"data.txt.encrypted\" (Encrypt with empty password)\n\n"
    "%s e -p \"your unique passphrase\" -hd \"header.txt\" \"data.txt\" \"data.txt.encrypted\"\n\n"
    "printf \"Hello World\" | %s e -p \"your unique passphrase\" -mem 250000000 \"\" \"message.enc\"\n\n"
    "tar -I \"zstd -6\" -c \".git\" | %s e -hd \"This is a backup repo v123\" -pf \"passfile.txt\" > \"gitRepo.enc\"\n\n"
    "%s d -p \"your unique passphrase\" \"message.enc\" (output to terminal)\n\n"
    "cat < \"gitRepo.enc\" | %s d -pf \"passfile.txt\" | tar -x --zstd\n\n"
    "%s hd -p \"your unique passphrase\" \"data.txt.encrypted\" \"header.txt\"\n\n"
    "cat < \"gitRepo.enc\" | %s t -pf \"passfile.txt\"\n\n\n"
    "Contribute improvement or report issues to <%s>.\n\n"
    ,
    SIG_V_TAG, SIG_V_NUMBER,
    appName, strLength, OPSLIMIT, MEMLIMIT, num2byte(MEMLIMIT,2), strLength, BUFFER_CHUNK, num2byte(BUFFER_CHUNK,2),
    strLength, strLength, MEMLIMIT, num2byte(MEMLIMIT,2),
    appName, appName, appName, appName, appName, appName, appName, appName, appName,
    REPO_URL
  );
}
// ============================== MAIN FUNCTION ===============================
int main(int argc, char *argv[]) {
  fprintf(stderr, "\n");
  if (sodium_init() != 0) {
    fprintf(stderr, "libsodium initialization failed!\n");
    return -1;
  }
  setbuf(stderr,NULL); // stderr printed immediately
  //setbuf(stdout,NULL); // stdout printed immediately
  setlocale(LC_ALL, "");
  setlocale(LC_NUMERIC, LCLOPT);
  char *appPath = argv[0];
  const char *modeOpt = argc==1 ? "" : argv[1];

  char *password = "", *ad = "", *passfile = "", *headerfile = "",
       *input_file = "", *output_file = "";
  long ops = (long) OPSLIMIT, mem = (long) MEMLIMIT;
  int i;
  for (i = 2; i < argc; i += 2) {
    if (i+1 >= argc) {
      break;
    }
    if (strcmp(argv[i],"-p") == 0) {
      password = argv[i+1];
    }
    else if (strcmp(argv[i],"-ad") == 0) {
      ad = argv[i+1];
    }
    else if (strcmp(argv[i],"-pf") == 0) {
      passfile = argv[i+1];
    }
    else if (strcmp(argv[i],"-hd") == 0) {
      headerfile = argv[i+1];
    }
    else if (strcmp(argv[i],"-ops") == 0) {
      if (*argv[i+1] != '\0' && str2l(&ops, argv[i+1], "'-ops' ") != 0) {
        return -1;
      }
    }
    else if (strcmp(argv[i],"-mem") == 0) {
      if (*argv[i+1] != '\0' && str2l(&mem, argv[i+1], "'-mem' ") != 0) {
        return -1;
      }
    }
    else {
      break;
    }
  }
  /*
  // Password can be empty
  if (*password == '\0' && *passfile == '\0') {
    fprintf(stderr,
      "Password is empty. Set your password using either '-p' or '-pf'.\n"
    );
    helper(appPath);
    return -1;
  }
  */
  input_file = i<argc ? argv[i] : "";
  output_file = i+1<argc ? argv[i+1] : "";
  /*
  printf(
    "-pf '%s' -p '%s' -ops '%ld' -mem '%ld' -ad '%s' -hd '%s' '%s' '%s'\n\n"
    "'%s' '%s'"
    ,
    passfile, password, ops, mem, ad, headerfile, input_file, output_file,
    appPath, modeOpt
  );
  return 0;
  */
  if (strcmp(modeOpt,"d") != 0 && strcmp(modeOpt,"e") != 0 && strcmp(modeOpt,"hd") != 0 && strcmp(modeOpt,"t") != 0) {
    helper(appPath);
    return *modeOpt == '\0' ? 0 : -1;
  }
  int retCode;
  if (strcmp(modeOpt,"e") == 0) {
    retCode = encrypt_file(input_file, output_file, passfile, headerfile, password, &ops, &mem, ad);
  }
  else if (strcmp(modeOpt,"d") == 0 || strcmp(modeOpt,"hd") == 0 || strcmp(modeOpt,"t") == 0) {
    retCode = decrypt_file(input_file, output_file, passfile, headerfile, password, &ops, &mem, ad, modeOpt);
  }
  sodium_memzero(password, strlen(password));
  sodium_memzero(passfile, strlen(passfile));
  return retCode;
}
#ifdef _WIN32
// ============================== WMAIN FUNCTION ==============================
// To process non-ascii arguments on Windows
int wmain(int argc, wchar_t *argv[]) {
  _setmode(_fileno(stdout), _O_BINARY);
  _setmode(_fileno(stdin), _O_BINARY);
  char **new_argv = (char **)malloc(argc * sizeof(char *));
  for (int i = 0; i < argc; i++) {
    new_argv[i] = wide2byte(argv[i]);
  }
  int send_to_main = main(argc, new_argv);
  for (int i = 0; i < argc; i++) {
    sodium_memzero(new_argv[i], strlen(new_argv[i]));
  }
  sodium_memzero(new_argv, argc);
  return send_to_main;
}
#endif
