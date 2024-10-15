#!/usr/bin/env bash

alias RUNAPPNAME='simplenc'

alias rung='time gccc "simplenc" "" -lsodium -g -municode'
# -g3 includes extra information, such as all the macro definitions present in the program.
alias rungw='rung -Wall'

alias rux1='time RUNAPPNAME e "會鼌國鼌心" "char.txt" "charEnc.txt"'
alias rux2='time RUNAPPNAME e "會鼌國鼌心" "會鼌國鼌心.txt" > "會鼌國鼌心.enc"'

alias runea='time RUNAPPNAME e "passa" "char.txt" "charEnc.txt"'
alias runet='time RUNAPPNAME e "pass.txt" "char.txt" "charEnc.txt"'
alias runem='time RUNAPPNAME e "會鼌國鼌心" "char.txt" "charEnc.txt"'

alias runda='time RUNAPPNAME d "passa" "charEnc.txt" "charDec.txt"'
alias rundt='time RUNAPPNAME d "pass.txt" "charEnc.txt" "charDec.txt"'
alias rundm='time RUNAPPNAME d "會鼌國鼌心" "charEnc.txt" "charDec.txt"'

alias runve1='time RUNAPPNAME e "pass.txt" video.mp4 > video.enc'
alias runve2='time cat < video.mp4 | RUNAPPNAME e "passa" > video.enc'

alias runvd1='time RUNAPPNAME d "pass.txt" video.enc > videoDec.mp4'
alias runvd2='time cat < video.enc | RUNAPPNAME d "passa" > videoDec.mp4'

alias cmppv='cmpp video.mp4 videoDec.mp4'

printf "\n%s\n\n" \
"================================= COMPILING ================================="

rungw && printf "\nSuccessfully Compiling!" || {
  printf "\nFailed To Compile!\n" && return 1
}

printf "\n\n%s\n\n" \
"================================ ENCRYPTING ================================"

runet && printf "\nSuccessfully Encrypting!" || {
  printf "\nFailed To Encrypt!\n" && return 1
}

printf "\n\n%s\n\n" \
"================================ DECRYPTING ================================="

rundt && printf "\nSuccessfully Decrypting!" || {
  printf "\nFailed To Decrypt!\n" && return 1
}

printf "\n\n%s\n\n" \
"============================ COMPARING CHAR.TXT ============================="

printf "cmp char.txt charDec.txt :\n$(cmpp char.txt charDec.txt)"

printf "\n"
