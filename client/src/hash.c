#include <stdio.h>								// Standard Input/Output library */
#include <stdlib.h>								// Standard Library */
#include <string.h>
#include <openssl/sha.h>

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
