#include <stdio.h>								// Standard Input/Output library */
#include <string.h>								// Use String Functions */
#include <sys/socket.h>							 	// Internet Protocol Family, needed to implement Socket 
#include <arpa/inet.h>								// Definitions for internet operations */
#include <unistd.h>								// Write/Read */
#include <stdlib.h>								// Standard Library */
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <openssl/sha.h>

extern unsigned char* hash_data(const char* data)
{
	SHA512_CTX context;
	//printf("\n\nDATA\n%s$\n\n", data);
	//data[strcspn(data, "\n")] = 0;
	//printf("\n\nDATA\n%s$\n\n", data);
	size_t data_length = strlen(data);
	static unsigned char checksum[SHA512_DIGEST_LENGTH];
	char* buffer = (char*)calloc(data_length, sizeof(unsigned char));

	memcpy(buffer, data, data_length);
	SHA512_Init(&context);
	SHA512_Update(&context, buffer, data_length);
	SHA512_Final(checksum, &context);

	free (buffer);

	printf("\n\nHASH FUNCTION\n\n");
	BIO_dump_fp(stdout, (const char *)checksum, strlen((const char *)checksum));
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
