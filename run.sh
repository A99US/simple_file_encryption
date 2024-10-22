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
