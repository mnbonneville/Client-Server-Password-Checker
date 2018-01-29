#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern int pass_pol(const char *s);
extern int brute_5(int i, char val);

extern int pass_pol(const char *s)
{
	int result = 0;
	int size = 0;
	size = strlen(s);
	if(size > 7)
	{
		result = 0x63;
	}
	else
	{
		result = 0x17;
		write(2, "Security Policy Violation.\n", 27);
	}

	return result;
}

extern int brute_5(int i, char val)
{
	int result = 0;
	if(i >= 5)
	{
		if(val == 'i')
		{
			result = 0x17;
			write(2, "Security Policy Violation.\n", 27);
		}
	}
	else
	{
		result = 0x63;
	}

	return result;
}
