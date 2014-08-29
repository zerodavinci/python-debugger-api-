#include<stdio.h>
#include<unistd.h>

int main()
{
	char str[30] = "I'm sleeping.....\n";
	while(1) {
		puts(str);
		sleep(1);
	}
}
