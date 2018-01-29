#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern int pass_pol(const char *s);
extern int c_max(int x);

extern int pass_pol(const char *s)
{
	int result = 0;
	int size = 0;
	size = strlen(s);
	if(size > 7)
	{
		result = 0x91;
	}
	else
	{
		result = 0x17;
		write(2, "Security Policy Violation.\n", 27);
	}
	
	return result;
}

extern int c_max(int x)
{
	int result = 0;
	if(x >= 5)
	{
		result = 0x43;
	}
	else
	{
		result = 0x91;
	}

	return result;
}
