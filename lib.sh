gcc -c -fPIC -nostdlib hitcon.c
gcc -shared -Wl,-soname,hitcon.so -o hitcon.so hitcon.o
