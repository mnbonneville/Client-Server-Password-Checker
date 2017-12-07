#include <stdio.h>
#include <openssl/sha.h>
#include <stdlib.h>
#include <string.h>

extern unsigned char* hash_data(const char* data)
{
	SHA512_CTX context;
	size_t data_length = strlen(data);
	static unsigned char checksum[SHA512_DIGEST_LENGTH];
	char* buffer = (char*)calloc(data_length, sizeof(unsigned char));

	memcpy(buffer, data, data_length);
	SHA512_Init(&context);
	SHA512_Update(&context, buffer, data_length);
	SHA512_Final(checksum, &context);

	free (buffer);
	return checksum;
}

/*#ifdef TEST
int main()
{
	int i;
	unsigned char* string;
	char* test_data = "adsfaeiovnahkshdsvpiaewnvakehffisdfakdsjadvaef";
	string = hash_data(test_data);
	printf("HASH VALUE = ");
	for(i = 0; i < SHA512_DIGEST_LENGTH; ++i)
	{
		printf("%x", string[i]);
	}

	printf("\n");
}
#endif*/

//-lcrypto -DTEST
