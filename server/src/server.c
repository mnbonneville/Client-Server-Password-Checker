/* Included Libraries for Functionality */
#include "../hdr/server.h"

/* Included Libraries for Functionality */
#include <sys/socket.h>							/* Internet Protocol Family, needed to implement Socket */
#include <arpa/inet.h>							/* Definitions for internet operations */
#include <stdio.h>							/* Standard Input/Output library */
#include <string.h>							/* Use String Functions */
#include <stdlib.h>							/* Standard Library */
#include <unistd.h>							/* Write/Read */
#include <pthread.h>							/* Used for Threading */
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

/* Define Size and Error Variables */
#define VALID_SIZE		16
#define INVALID_SIZE		18
#define PASS_SIZE		50
#define MSG_SIZE		128
#define INIT_FAIL		0x3
#define VALID_FAIL		0x7
#define	INVALID_FAIL		0x11
#define	INIT_PASS		0x15
#define PW_FAIL			0x19
#define FILE_OPEN_FAIL		0x23	
#define	READ_PASS		0x27
#define SOCK_CREATE_FAIL	0x31
#define SOCK_CREATE_PASS	0x35
#define	BIND_FAIL		0x39
#define LISTEN_FAIL		0x43
#define BIND_LISTEN_PASS	0x47
#define S_ALLOC_FAIL		0x51
#define NEW_SOCK_ALLOC_FAIL	0x55
#define THREAD_FAIL		0x59
#define THREAD_PASS		0x63
#define ACCEPT_FAIL		0x67
#define CLIENT_FAIL		0x71
#define CLIENT_PASS		0x75
#define DT_FAIL			0x79

extern int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext);
extern int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext);
extern void handleErrors(void);

/* Declaration of Global Variables and Initialization of pointers to NULL */
int beginSocket = 0;
int acceptSocket = 0;
int *s = NULL;
int *new_socket = NULL;							// Sockets used
int status = 0;
int bind_state = -1;
int listen_state = -1;
struct sockaddr_in server, client;					// Server client connection information
char *pass = NULL;							// Password from file
char *valid = NULL;							// Valid response
char *invalid = NULL;							// Invalid response
uint8_t *key;
uint8_t *iv;
uint8_t *decryptedtext = NULL;
int decryptedtext_len = 0;
//int ciphertext_len;

/* Main function for testing */
int main(int argc, char *argv[])
{
	/* Initialise the library */
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);

	initval();
	if(status == INIT_PASS)
	{
		readf();
		if(status == READ_PASS)
		{
			create_socket();
			if(status == SOCK_CREATE_PASS)
			{
				bind_listen();
				if(status == BIND_LISTEN_PASS)
				{
					accept_client();
				}
				else
				{
					write(2, &status, sizeof(status));
				}
			}			
			else
			{
				write(2, &status, sizeof(status));
			}
		}
		else
		{
			write(2, &status, sizeof(status));
		}
	}
	else
	{
		write(2, &status, sizeof(status));
	}
	/* Clean up */
	EVP_cleanup();
	ERR_free_strings();
	return 0;
}

/* Function to allocate valid and pointer variables to the heap */
int initval(void)
{
	status = INIT_FAIL;
	valid = (char *)calloc(VALID_SIZE,sizeof(char));			// Allocate space for a 20 character string
	if(valid < 0)
	{
		status = VALID_FAIL;
	}
	else
	{
		invalid = (char *)calloc(INVALID_SIZE,sizeof(char));		// Allocate space for a 20 character string
		if(invalid < 0)
		{
			status = INVALID_FAIL;
		}
		else
		{	
			decryptedtext = (uint8_t *)calloc(MSG_SIZE,sizeof(uint8_t));
			if(decryptedtext < 0)
			{
				status = DT_FAIL;
			}
			else
			{
				status = INIT_PASS;
				key = (uint8_t *)"01234567890123456789012345678901";
				iv = (uint8_t *)"0123456789012345";
				valid = "Valid Password.\n";			// Assign value to Valid
				invalid = "Invalid Password.\n";		// Assign value to Invalid
			}
		}
	}
	return status;
}

/* Open, read, and store the password from the passwords file */
int readf(void)
{
	status = 0;
	pass = (char *)calloc(PASS_SIZE,sizeof(char));				// Allocate 50 character string for the password
	if(pass < 0)
	{
		status = PW_FAIL;
	}
	else
	{
		FILE *fp = fopen("../data/passwords.txt","r");			// Open file
		if(!fp)								// If file doesn't open
		{
			write(2, "Could not find the file\n", 24);		// Print error
			status = FILE_OPEN_FAIL;				// Exit the function and program
		}
		else
		{
			fgets(pass, PASS_SIZE, fp);				// Store the password
			pass[strcspn(pass, "\n")] = 0;				// Erase null character
			status = READ_PASS;
		}
		fclose(fp);							// Close file
	}
	return status;
}

/* Create socket and configure the server settings */
int create_socket(void)
{
	status = 0;
	/* Create Socket */
	beginSocket = socket(AF_INET, SOCK_STREAM, 0);				// Initialize socket to the proper address family and stream
	if (beginSocket == -1)							// If initalization fails
	{
		write(2, "Could not create socket\n", 24);			// Print error
		status = SOCK_CREATE_FAIL;					// Exit the function and program
	}
	else
	{
		/* Configure Server Address Struct */
		server.sin_family = AF_INET;					// Set server address family
		server.sin_port = htons(9993);					// Set server port to 9993
		server.sin_addr.s_addr = inet_addr("127.0.0.1");		// Set server ip to 127.0.0.1
		status = SOCK_CREATE_PASS;
	}
	return status;
}

int bind_listen(void)
{
	/* Bind Address Struct to the Socket */
	bind_state = bind(beginSocket, (struct sockaddr*)&server, sizeof(server));
	if(bind_state < 0)	// If bind fails
	{
		write(2, "Bind failed\n", 12);					// Print error
		status = BIND_FAIL;						// Exit the function and program
	}
	else
	{
		/* Listen for Client */
		listen_state = listen(beginSocket, 5);				// Allow for 5 different clients
		if(listen_state < 0)
		{
			write(2, "Listening Failed.\n", 18);
			status = LISTEN_FAIL;
		}
		else
		{
			write(1, "Listening...\n", 13);				// Tell that server is listening
			status = BIND_LISTEN_PASS;
		}
	}
	return status;
}

int accept_client(void)
{
	status = 0;
	/* Accept Call and Create new socket for connection */
	s = calloc(1, sizeof(struct sockaddr_in));				// Allocate memory for s
	if(s < 0)
	{
		write(2, "Memory Allocation for s failed.\n", 30);
		status = S_ALLOC_FAIL;
	}
	else
	{ 
		while((acceptSocket = accept(beginSocket, (struct sockaddr*)&client, (socklen_t*)&s)))		// While connection accepts
		{
			write(1, "Connection Accepted\n", 20);							// Print confirmation

			/* Set Up Threading */
			pthread_t sniffer_thread;				// Declare thread
			new_socket = calloc(1, sizeof(char));			// Allocate memory
			if(new_socket < 0)
			{
				write(2, "Memory Allocation for New Socket Fail.\n", 39);
				status = NEW_SOCK_ALLOC_FAIL;
			}
			else
			{
				*new_socket = acceptSocket;			// Set new socket to specific client

				/* Join the thread */
				if (pthread_create(&sniffer_thread, NULL, connection_handler,(void*)new_socket)<0)
				{
					write(2, "Could Not Create Thread\n", 24);
					status = THREAD_FAIL;
				}
				else
				{
					write(1, "Client Assigned\n", 16); 	// Print client assigned
					status = THREAD_PASS;
				}
			}		
		}
		if (acceptSocket<0)						// If socket fails
		{
			write(2, "Accept failed\n", 14);			// Print error
			status = ACCEPT_FAIL;
		}
	}
	return status;
}

/* Function to handle individual client connection */
void *connection_handler(void *socket_s)
{
	status = 0;
	/* Get socket */
	int socket = *(int*)socket_s;						// Declare socket
	int read_size;								// Declare read_size
	char *client_message = (char *)calloc(MSG_SIZE,sizeof(char));		// Allocate memory for client message

	/* Receive Client Input */
	while((read_size = recv(socket, client_message, 128, 0))>0)		// While client is open
	{
		decryptedtext_len = decrypt((uint8_t *)client_message, read_size, key, iv, decryptedtext);
		decryptedtext[strcspn((char *)decryptedtext, "\n")] = 0;

		/* Check password */
		if(strcmp((char *)decryptedtext, pass) == 0)			// If message is the same as the password
		{
			write(socket, valid, VALID_SIZE);			// Print valid
		}
		else/*if(strcmp((char *)decryptedtext, pass) != 0)*/		// If message is not the same as the password
		{
			write(socket, invalid, INVALID_SIZE);			// Print invalid
		}

		free(client_message);						// Free allocated memory
		client_message = (char *)calloc(MSG_SIZE,sizeof(char));		// Allocate new memory to password
	}

	if(read_size==0)							// If nothing is received
	{
		write(1, "Client Disconnected\n", 20);				// Print disconnected
		fflush(stdout);							// Flush the stdout
		status = CLIENT_PASS;
	}
	else if(read_size==-1)							// If receive fails
	{
		write(2, "recv failed\n", 12);					// Print error
		status = CLIENT_FAIL;
	}

	/* Free Socket Pointer */
	close(socket);
	free(socket_s);

	return &status;
}
