#!/bin/bash
rm -f index.html
if [ ! -x xor ]
then
  gcc -O2 -o xor xor.c
fi
#
wget -O - http://www.lemonde.fr | tr -d ">< \t\m\n" | ./xor >> index.html
dd if=/dev/urandom count=4 | ./xor >>index.html
echo `ps -ef` `ls -lR /etc` | tr -d " \t\m\n" | ./xor >> index.html
date | ./xor >> index.html

#
wget -O - http://www.nytimes.com | tr -d ">< \t\m\n" | ./xor >> index.html
dd if=/dev/urandom count=4 | ./xor >>index.html
echo `ps -ef` `ls -lR /etc` | tr -d " \t\m\n" | ./xor >> index.html
date | ./xor >> index.html

#
wget -O - http://www.latimes.com | tr -d ">< \t\m\n" | ./xor >> index.html
dd if=/dev/urandom count=4 | ./xor >>index.html
echo `ps -ef` `ls -lR /etc` | tr -d " \t\m\n" | ./xor >> index.html
date | ./xor >> index.html

#
wget -O - http://news.bbc.co.uk | tr -d ">< \t\m\n" | ./xor >> index.html
dd if=/dev/urandom count=4 | ./xor >>index.html
echo `ps -ef` `ls -lR /etc` | tr -d " \t\m\n" | ./xor >> index.html
date | ./xor >> index.html

#
wget -O - http://www.washingtonpost.com | tr -d ">< \t\m\n" | ./xor >> index.html
dd if=/dev/urandom count=4 | ./xor >>index.html
echo `ps -ef` `ls -lR /var` | tr -d " \t\m\n" | ./xor >> index.html
date | ./xor >> index.html

#
wget -O - http://www.aljazeera.com | tr -d ">< \t\m\n" | ./xor >> index.html
dd if=/dev/urandom count=4 | ./xor >>index.html
echo `ps -ef` `ls -lR /var` | tr -d " \t\m\n" | ./xor >> index.html
date | ./xor >> index.html



