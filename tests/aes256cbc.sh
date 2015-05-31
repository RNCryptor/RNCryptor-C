#!/bin/sh
#
# quick test with openssl for sanity check of test vectors
# muquit@muquit.com May-31-2015 
# NULL data
#key="0000000000000000000000000000000000000000000000000000000000000000"
key="00000000000000000000000000000000"
iv="00000000000000000000000000000000"
/bin/rm -f /tmp/infile
touch /tmp/infile
infile="/tmp/infile"
#openssl enc -aes-128-cbc -in $infile -K $key -iv $iv | hod
key='d2cc92e9115a8d1665640514505d9e3ef37fd8af5c026428cece22f0cd3406f7'
openssl enc -aes-256-cbc -in $infile -K $key -iv $iv | hod
key="3870f80199d0e09fcde75ba734d2030105912992d0bcddf64cf6bfda37adbfcc"
key="c3a6bc6b9d9b7ed4298d0480e43096e3848a740ce1cf9b219ae552f12a09297b"
iv="02030405060708090a0b0c0d0e0f0001"
infile=/tmp/infile
/bin/rm -f $infile
/bin/echo -n 01|hod -w > $infile
/bin/ls -lt $infile
openssl enc -aes-256-cbc -in $infile -K $key -iv $iv | hod
