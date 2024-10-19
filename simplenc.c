#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <locale.h>
#include <sys/time.h>

// #if defined(_WIN32) || defined(_WIN64)
// _WIN32 for both 32 and 64
// _WIN64 specifically for 64
#ifdef _WIN32
  #include <windows.h>
  #include <wchar.h>
  #include <fcntl.h>
  #include <io.h>
  #define PLTFRM "WIN"
  #define LCLOPT "id_ID" //"Indonesian_Indonesia.1252" //"id_ID.utf8" //
#else
  #define PLTFRM "NIX"
  #define LCLOPT "id_ID.UTF-8"
#endif

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
    fprintf(stderr, "%sDoesn't Contain Any Digit! (\"%s\")\n", text, line);
    return -1;
  }
  else if ((*num == LONG_MAX || *num == LONG_MIN) && errno == ERANGE) {
    fprintf(stderr, "%sNumber Is Out of Range! (\"%s\")\n", text, line);
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
static int pass_file_fetcher(const char *input_pass, char *pass, char *ad, long *ops, long *mem) {
  int retCode = -1;
  FILE *passFile = NULL;
  if (strcmp(PLTFRM,"WIN") == 0) {
    passFile = _wfopen((wchar_t *)byte2wide(input_pass), L"rb");
  }
  else {
    passFile = fopen(input_pass, "rb");
  }
  fseek(passFile, 0, SEEK_END);
  long pass_size = ftell(passFile);
  fseek(passFile, 0, SEEK_SET);
  if (passFile && pass_size > 0) {
    size_t line_limit = ARGON2_STRING_LIMIT + 5;
    char line[line_limit];
    int id = 0;
    while (fgets(line, line_limit, passFile) != NULL && id < 4) {
      line_sanitizer(line);
      size_t lineLn = strlen(line);
      char *idString = id == 0 ? "Passphrase" : "Ad";
      if (id < 2 && lineLn >= ARGON2_STRING_LIMIT) {
        fprintf(stderr,"%s Strings is longer than %d chars!\n", idString, (ARGON2_STRING_LIMIT-1));
        goto retPoint;
      }
      //fprintf(stderr,"%d. \"%s\" : \"%d\"\n", id, line, lineLn); //exit(0);
      if (id == 0) {
        strncpy(pass,line,lineLn); pass[lineLn] = '\0';
      }
      if (id == 1) {
        strncpy(ad,line,lineLn); ad[lineLn] = '\0';
      }
      else if (id == 2 && lineLn > 0 && str2l(&*ops, line, "Opslimit ") != 0) {
        goto retPoint;
      }
      else if (id == 3 && lineLn > 0 && str2l(&*mem, line, "Memlimit ") != 0) {
        goto retPoint;
      }
      id++;
    }
    retCode = 0;
retPoint:
    sodium_memzero(line, sizeof line);
    fclose(passFile);
    return retCode;
  }
  else if (passFile) {
    // Empty file, empty passphrase. Return 0
    return 0;
  }
  else if (!passFile) {
    if (strlen(input_pass) >= ARGON2_STRING_LIMIT) {
      fprintf(stderr, "Passphrase Strings is longer than %d chars!\n", ARGON2_STRING_LIMIT-1);
      return -1;
    }
    strncpy(pass,input_pass,strlen(input_pass));
    pass[strlen(input_pass)] = '\0';
    return 0;
  }
  return retCode;
}
// =========================== ENCRYPTION FUNCTION ============================
static int encrypt_file ( const char *input_file, const char *output_file, const char *password ) {
  int retCode = -1;
  // Vars for Argon2
  unsigned char key[KEY_SIZE];
  unsigned char salt[SALT_SIZE];
  randombytes_buf(salt, SALT_SIZE);
  char passVal[ARGON2_STRING_LIMIT] = "";
  char adVal[ARGON2_STRING_LIMIT] = "";
  long opsVal = OPSLIMIT;
  long memVal = MEMLIMIT;
  // Vars for SecretStream
  unsigned char buf_in[BUFFER_CHUNK];
  unsigned char buf_out[BUFFER_CHUNK + TAG_SIZE];
  unsigned char header[HEADER_SIZE];
  crypto_secretstream_xchacha20poly1305_state st;
  unsigned long long out_len;
  size_t rlen;
  int eof;
  unsigned char tag;
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
  if (pass_file_fetcher(password,passVal,adVal,&opsVal,&memVal) != 0) {
    goto retPoint1;
  }
  if (argon2key(key, passVal, salt, &opsVal, &memVal) != 0) {
    goto retPoint2;
  }
  //fprintf(stderr,"\n\"%s\" \"%s\" \"%s\" \"%s\" \"%ld\" \"%ld\"\n\n", input_file, output_file, passVal, adVal, opsVal, memVal); //exit(0);
  fwrite(salt, 1, SALT_SIZE, data_output);
  if (crypto_secretstream_xchacha20poly1305_init_push(&st, header, key) != 0) {
    fprintf(stderr, "Failed to create header!\n");
    goto retPoint3;
  }
  fwrite(header, 1, sizeof header, data_output);
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
static int decrypt_file ( const char *input_file, const char *output_file, const char *password ) {
  int retCode = -1;
  // Vars for Argon2
  unsigned char key[KEY_SIZE];
  unsigned char salt[SALT_SIZE];
  char passVal[ARGON2_STRING_LIMIT] = "";
  char adVal[ARGON2_STRING_LIMIT] = "";
  long opsVal = OPSLIMIT;
  long memVal = MEMLIMIT;
  // Vars for SecretStream
  unsigned char buf_in[BUFFER_CHUNK + TAG_SIZE];
  unsigned char buf_out[BUFFER_CHUNK];
  unsigned char header[HEADER_SIZE];
  crypto_secretstream_xchacha20poly1305_state st;
  unsigned long long out_len;
  size_t rlen;
  int eof;
  unsigned char tag;
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
  if (pass_file_fetcher(password,passVal,adVal,&opsVal,&memVal) != 0) {
    goto retPoint1;
  }
  fread(salt, 1, SALT_SIZE, data_input);
  if (argon2key(key, passVal, salt, &opsVal, &memVal) != 0) {
    goto retPoint2;
  }
  //fprintf(stderr,"\n\"%s\" \"%s\" \"%s\" \"%s\" \"%ld\" \"%ld\"\n", input_file, output_file, passVal, adVal, opsVal, memVal); //exit(0);
  fread(header, 1, HEADER_SIZE, data_input);
  if (crypto_secretstream_xchacha20poly1305_init_pull(&st, header, key) != 0) {
    /* incomplete header */
    fprintf(stderr, "Corrupted header!\n");
    goto retPoint3;
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
    fwrite(buf_out, 1, (size_t) out_len, data_output);
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
  fprintf(stderr, "\n\nDecryption completed in %.2f second%s\n", duration, duration>=2?"s":"");
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
// ============================== MAIN FUNCTION ===============================
int main(int argc, char *argv[]) {
  fprintf(stderr, "\n");
  if (strcmp(PLTFRM,"NIX") == 0 && sodium_init() != 0) {
    fprintf(stderr, "libsodium initialization failed!\n");
    return -1;
  }
  setbuf(stderr,NULL); // stderr printed immediately
  setlocale(LC_ALL, "");
  setlocale(LC_NUMERIC, LCLOPT);
  char *appPath = argv[0];
  const char *modeOpt = argv[1];
  char *password = argv[2];
  const char *input_file = argc < 4 ? "" : argv[3];
  const char *output_file = argc < 5 ? "" : argv[4];
  //fprintf(stderr, "\"%s\" \"%s\" \"%s\" \"%s\"\n", appPath, modeOpt, password, input_file); exit(0);
  if (argc < 3) {
    modeOpt = "h";
  }
  if (strcmp(modeOpt,"d") != 0 && strcmp(modeOpt,"e") != 0) {
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
      "\n\nSimple File Encryption v1.0.0\n\n"
      "Library      : Libsodium\n"
      "KDF Algo     : Argon2 (ARGON2ID13)\n"
      "Cipher Algo  : XChaCha20-Poly1305 (Stream Encryption)\n\n\n"
      "Commands : \n\n"
      "%s <mode> <pass_file> <input_file> <output_file||null>\n\n"
      "stdout | %s <mode> <pass_file> \"\" <output_file||null>\n\n\n"
      "- mode         : e -> To encrypt\n"
      "                 d -> To decrypt\n"
      "- pass_file    : File that contain passphrase, ad strings,\n"
      "                 opslimit and memlimit. If it's not a file,\n"
      "                 then it will be treated as the choosen passphrase.\n"
      "- input_file   : File to process. If not provided / empty,\n"
      "                 will process stdin instead.\n"
      "- output_file  : File to save result to. If not provided / empty,\n"
      "                 will output to terminal instead.\n\n\n"
      "\"pass_file\" rules :\n\n"
      "- 1st line is the passphrase. %d chars max. Can be empty.\n"
      "- 2nd line is the ad strings. %d chars max. Can be empty.\n"
      "- 3rd line is the opslimit. Default 3 on empty.\n"
      "- 4th line is the memlimit. Default %d on empty.\n\n\n"
      "Warning : \n\n"
      "- If \"output_file\" already exist, program will OVERWRITE it automatically.\n"
      "  It will not ask for an overwrite confirmation.\n\n\n"
      "Command Example :\n\n"
      "%s (No argument will default to show help)\n\n"
      "%s e \"your unique passphrase\" \"data.txt\" \"data.txt.encrypted\"\n\n"
      "printf \"Hello World\" | %s e \"your unique passphrase\" \"\" \"message.enc\"\n\n"
      "tar -I \"zstd -6\" -c \".git\" | %s e \"passfile.txt\" > \"gitRepo.enc\"\n\n"
      "%s d \"your unique passphrase\" \"message.enc\" (output to terminal)\n\n"
      "cat < \"gitRepo.enc\" | %s d \"passfile.txt\" | tar -x --zstd\n"
      ,
      appName, appName,
      strLength, strLength, MEMLIMIT,
      appName, appName, appName, appName, appName, appName
    );
    exit(0);
  }
  int retCode;
  if (strcmp(modeOpt,"e") == 0) {
    retCode = encrypt_file(input_file, output_file, password);
  }
  else if (strcmp(modeOpt,"d") == 0) {
    retCode = decrypt_file(input_file, output_file, password);
  }
  sodium_memzero(password, strlen(password));
  return retCode;
}
#ifdef _WIN32
// ============================== WMAIN FUNCTION ==============================
// To process non-ascii arguments on Windows
int wmain(int argc, wchar_t *argv[]) {
  if (sodium_init() != 0) {
    fprintf(stderr, "\nlibsodium initialization failed!\n");
    return -1;
  }
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
