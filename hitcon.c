#include<stdio.h>
#include<string.h>
// inject so
static int i = 1;

static void inline __attribute__((always_inline)) pattern() 
{
	asm("nop");
	asm("nop");
	asm("nop");
	asm("xchg %r15,%r15");
}


static void inline __attribute__((always_inline)) backup()
{
	asm("pushfq");
	asm("push %rax");
	asm("push %rbx");
	asm("push %rcx");
	asm("push %rdx");
	asm("push %rsi");
	asm("push %rdi");
	asm("push %r8");
	asm("push %r9");
	asm("push %r10");
	asm("push %r11");
	asm("push %r12");
	asm("push %r13");
	asm("push %r14");
	asm("push %r15");

}

static void inline __attribute__((always_inline)) restore()
{
	asm("pop %r15");
	asm("pop %r14");
	asm("pop %r13");
	asm("pop %r12");
	asm("pop %r11");
	asm("pop %r10");
	asm("pop %r9");
	asm("pop %r8");
	asm("pop %rdi");
	asm("pop %rsi");
	asm("pop %rdx");
	asm("pop %rcx");
	asm("pop %rbx");
	asm("pop %rax");
	asm("popfq");
}

int hello()
{
	backup();
	// do something
	printf("Hooked %d\n",i);
	i++;

	// do something

	restore();
	asm("leave"); // mov %rbp,%rsp , pop %rpb 有讀參數就用這個
	// backup r15
	asm("sub $16,%rsp");
	asm("mov %r15,(%rsp)"); 
	asm("add $16,%rsp");
	
	// 跳回去
	pattern();
	asm("mov $0x4141414141414141,%r15");
	asm("push %r15");

	// restore r15
	asm("sub $8,%rsp");
	asm("mov (%rsp),%r15");
	asm("add $8,%rsp");

	asm("ret");

}
