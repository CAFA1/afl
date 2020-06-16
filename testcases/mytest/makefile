all:
	gcc  -o mytest mytest.c
fuzz:
	AFL_PATH=/home/l/AFL ~/AFL/afl-fuzz -i in -o out -Q -- ./mytest