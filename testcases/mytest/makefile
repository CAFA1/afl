llvm:
	~/AFL/afl-clang-fast -o mytest mytest.c
gcc:
	gcc  -o mytest mytest.c
fuzz:
	AFL_PATH=/home/l/AFL ~/AFL/afl-fuzz -i in -o out -Q -- ./mytest
trace:
	/home/l/AFL/afl-qemu-trace -d in_asm,exec -- ./mytest 
trace1:
	/home/l/AFL/afl-qemu-trace -d in_asm,out_asm,op,exec,cpu -- ./mytest 