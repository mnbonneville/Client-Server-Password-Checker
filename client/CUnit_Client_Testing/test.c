#include "test.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int pass_pol(const char *s)
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
	}

	return result;
}

int brute_5(int i, char val)
{
	int result = 0;
	if(i >= 5)
	{
		if(val == 'i')
		{
			result = 0x17;
		}
	}
	else
	{
		result = 0x63;
	}

	return result;
}
