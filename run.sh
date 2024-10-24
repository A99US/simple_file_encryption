#!/usr/bin/env bash

alias RUNAPPNAME='simplenc'

alias rung='time gccc "simplenc" "" -lsodium -g -municode -lws2_32'
# -g3 includes extra information, such as all the macro definitions present in the program.
alias rungw='rung -Wall'

alias runea='time RUNAPPNAME e -p "會鼌國鼌心" -mem 10000 -hd "header.txt" "char.txt" "charEnc.txt"'
alias runet='time RUNAPPNAME e -pf "pass.txt" -hd "header.txt" "char.txt" "charEnc.txt"'

alias runda='time RUNAPPNAME d -p "會鼌國鼌心" -mem 10000 "charEnc.txt" "charDec.txt"'
alias rundt='time RUNAPPNAME d -pf "pass.txt" "charEnc.txt" "charDec.txt"'
alias rundo='time RUNAPPNAME d -pf "pass.txt" "charEnc.txt"'

alias runhda='RUNAPPNAME hd -p "會鼌國鼌心" -mem 10000 "charEnc.txt" "charDec.txt"'
alias runhdt='RUNAPPNAME hd -pf "pass.txt" "charEnc.txt" "charDec.txt"'
alias runhdo='RUNAPPNAME hd -pf "pass.txt" "charEnc.txt"'

alias runve1='time RUNAPPNAME e -pf "pass.txt" video.mp4 > video.enc'
alias runve2='time cat < video.mp4 | RUNAPPNAME e -p "會鼌國鼌心" -mem 10000 > video.enc'

alias runvd1='time RUNAPPNAME d -pf "pass.txt" video.enc > videoDec.mp4'
alias runvd2='time cat < video.enc | RUNAPPNAME d -p "會鼌國鼌心" -mem 10000 > videoDec.mp4'

alias cmppv='cmpp video.mp4 videoDec.mp4'

function runn(){
  local sep="=============================";

  printf "\n%s\n\n" "${sep} COMPILING ${sep}"

  rungw && printf "\nSuccessfully Compiling!" || {
    printf "\nFailed To Compile!\n" && return 1
  }

  printf "\n\n%s\n\n" "${sep} ENCRYPTING ${sep}"

  runet && printf "\nSuccessfully Encrypting!" || {
    printf "\nFailed To Encrypt!\n" && return 1
  }

  printf "\n\n%s\n\n" "${sep} DECRYPTING ${sep}"

  rundt && printf "\nSuccessfully Decrypting!" || {
    printf "\nFailed To Decrypt!\n" && return 1
  }

  printf "\n\n%s\n\n" "${sep} COMPARING CHAR.TXT ${sep}"

  printf "cmp char.txt charDec.txt :\n$(cmpp char.txt charDec.txt)"

  printf "\n"
}
function includes() {
  local item value="$1"; shift
  for item in "${@}"; do
    [[ "$item" == "$value" ]] && return 0
  done
  return 1
}
function simpled() {
  printf "\n"
  local bkpFileExt bkpFilePath changed="" nbu="" oldTime newTime \
        tempDir tempHeader tempFile \
        pf="" p="" ops="" mem="" ad="" hd="" f=""
  while includes "$1" "-pf" "-p" "-ops" "-mem" "-ad" "-hd" "-f" "-nbu"; do
    if [[ "$1" == "-pf" ]]; then
      pf="$2"; shift
    elif [[ "$1" == "-p" ]]; then
      p="$2"; shift
    elif [[ "$1" == "-ops" ]]; then
      ops="$2"; shift
    elif [[ "$1" == "-mem" ]]; then
      mem="$2"; shift
    elif [[ "$1" == "-ad" ]]; then
      ad="$2"; shift
    elif [[ "$1" == "-hd" ]]; then
      hd="$2"; shift
    elif [[ "$1" == "-f" ]]; then
      f="$2"; shift
    elif [[ "$1" == "-nbu" ]]; then
      nbu="true"
    fi
    shift
  done
  # RUNAPPNAME "$opt" -pf "$pf" -p "$p" -ops "$ops" -mem "$mem" -ad "$ad" "$1" "$2"
  tempDir="$(mktemp -d)" || {
    printf "%s\n" "Can't Create Temp Folder!" && return 1
  }
  tempHeader="$(mktemp -p "$tempDir")" || {
    printf "%s\n" "Can't Create Temp File For File Header!" && return 1
  }
  tempFile="$(mktemp -p "$tempDir")" || {
    printf "%s\n" "Can't Create Temp File For File Content!" && return 1
  }
  trap 'shred -fzu -n5 "$tempHeader"; shred -fzu -n5 "$tempFile"; rm -rf "$tempDir";' EXIT
  if [[ "$hd" == "" ]]; then
    printf "%s\n\n" "Decrypting Header . . . ."
    RUNAPPNAME hd -pf "$pf" -p "$p" -ops "$ops" -mem "$mem" -ad "$ad" "$1" "$tempHeader" 2>/dev/null
    [[ $? > 0 ]] && printf "%s\n" "Header Decryption Failed!" && return 1
    oldTime=$(stat -c %Y "$tempHeader")
    sleep 1
    nano "$tempHeader"
    if [[ $(stat -c %Y "$tempHeader") == $oldTime ]]; then
      printf "%s\n\n" "File Header was unchanged . . . ."
    else
      printf "%s\n\n" "File Header was changed . . . ."
      changed="true"
    fi
    hd="$tempHeader"
  else
    printf "%s\n\n" "Updating Header from file \"$hd\" . . . ."
    changed="true"
  fi
  if [[ "$f" == "" ]]; then
    printf "%s\n\n" "Decrypting Content . . . ."
    RUNAPPNAME d -pf "$pf" -p "$p" -ops "$ops" -mem "$mem" -ad "$ad" "$1" "$tempFile" 2>/dev/null
    [[ $? > 0 ]] && printf "%s\n" "Content Decryption Failed!" && return 1
    oldTime=$(stat -c %Y "$tempFile")
    sleep 1
    nano "$tempFile"
    if [[ $(stat -c %Y "$tempFile") == $oldTime ]]; then
      printf "%s\n\n" "File Content was unchanged . . . ."
    else
      printf "%s\n\n" "File Content was changed . . . ."
      changed="true"
    fi
    f="$tempFile"
  else
    printf "%s\n\n" "Updating Content from file \"$f\" . . . ."
    changed="true"
  fi
  if [[ "$changed" == "true" ]]; then
    printf "%s\n\n" "Re-Encrypting . . . ."
    bkpFileExt=".$(date +"%y%m%d%H%M%S").bkp"
    bkpFilePath="${1}${bkpFileExt}"
    mv "$1" "${bkpFilePath}"
    RUNAPPNAME e -pf "$pf" -p "$p" -ops "$ops" -mem "$mem" -ad "$ad" -hd "$hd" "$f" "$1" 2>/dev/null
    [[ $? > 0 ]] &&
      printf "%s\n\n" "Re-Encryption failed. Modification was not saved." &&
      mv "${bkpFilePath}" "$1" && return 1 ||
      printf "%s\n\n" "Re-Encryption was successfull."
    [[ -z "$nbu" ]] &&
      printf "%s\n\n" "Backup file was saved to \"${bkpFilePath}\"." || {
      printf "%s\n\n" "Backup option was disabled. Shredding Backup File . . . . "
      shred -fzu -n5 "${bkpFilePath}"
    }
  else
    printf "%s\n\n" "There was no change made. Nothing to save."
  fi
  printf "%s\n" "Shredding temp Files . . . ."
  shred -fzu -n5 "$tempHeader"; shred -fzu -n5 "$tempFile"; rm -rf "$tempDir";
  return 0
}
