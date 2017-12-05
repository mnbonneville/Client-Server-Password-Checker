// Included Header File */
#include "../hdr/client.h"

// Included Libraries for functionality */
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

// Define Size and Error Variables */
#define MSG_SIZE 50
#define RPLY_SIZE 20
#define INIT_FAIL 0x57
#define MSG_MEM_ALLOC_FAIL 0x43
#define SRV_MEM_ALLOC_FAIL 0x68
#define INIT_SUCCESS 0x32
#define CONNECT_SUCCESS 0x52
#define CONNECT_FAIL 0x17
#define SOCK_CREATE_FAIL 0x28
#define SOCK_CREATE_SUCCESS 0x11
#define SEND_FAIL 0x3
#define RECV_FAIL 0x7
#define COMMUNICATE_SUCCESS 0x77
#define CT_FAIL 0x63

extern int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext);
extern int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext);
extern void handleErrors(void);

// Declaration of Global Variables and Initialization of pointers to NULL */
int sockt = 0;									// Socket used to communicate with the server
struct sockaddr_in server;							// To hold server connection information
uint8_t *message = NULL;							// Password from input
char *server_reply = NULL;							// Reply from server
int send_state = 0;
int recv_state = 0;
int status = 0;
uint8_t *key = NULL;
uint8_t *iv = NULL;
uint8_t *ciphertext = NULL;
int ciphertext_len;

// Main function for testing */
int main()
{
	// Initialise the library */
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);

	create_socket();
	if(status == SOCK_CREATE_SUCCESS){
		status = connect_server();
		if(status == CONNECT_SUCCESS){
			communicate();}}
	// Clean up */
	EVP_cleanup();
	ERR_free_strings();
	return 0;
}

// Function to allocate pointer variables to the heap */
int initialize_var(void)
{
	status = 0;
	// that typedef thing */ status = INIT_FAIL;
	message = (uint8_t *)calloc((MSG_SIZE),sizeof(uint8_t));		// Allocate space for a 50 character string for the password input
	if (message < 0)
	{
		status = MSG_MEM_ALLOC_FAIL;
	}
	else
	{
		server_reply = (char *)calloc((RPLY_SIZE),sizeof(char));	// Allocate space for a 20 character string for the server response
		if (server_reply < 0)
		{
			status = SRV_MEM_ALLOC_FAIL;
		}
		else
		{
			ciphertext = (uint8_t *)calloc(MSG_SIZE,sizeof(uint8_t));
			if(ciphertext < 0)
			{
				status = CT_FAIL;
			}
			else
			{		
				status = INIT_SUCCESS;
				key = (uint8_t *)"01234567890123456789012345678901";
				iv = (uint8_t *)"0123456789012345";
			}
		}
	}
	return status;
}

// Create Socket to communicate with the server and set specifications for the server connection */
int create_socket(void)
{
	status = 0;
	// Create Socket */
	sockt = socket(AF_INET, SOCK_STREAM, 0);				// Initialize socket to the proper address family and stream
	if (sockt == -1)							// If initalization fails
	{
		write(2, "Socket creation error\n", 22);			// Print error
		status = SOCK_CREATE_FAIL;					// Exit the function and program
	}
	else
	{
		status = SOCK_CREATE_SUCCESS;
	}

	// Set server specifications */
	server.sin_addr.s_addr = inet_addr("127.0.0.1");			// Set server ip to 127.0.0.1
	server.sin_family = AF_INET;						// Set server address family
	server.sin_port = htons(9993);						// Set port to 9993

	return status;
}

// Connect to the server */
int connect_server(void)
{
	status = 0;
	int connect_state = connect(sockt, (struct sockaddr *)&server, sizeof(server));
	if(connect_state < 0)	// If server does not connect
	{
		write(2, "Server connection failed\n", 25);			// Print error
		status = CONNECT_FAIL;						// Exit the function and program
	}
	else
	{
		write(1, "Connected to Server\n", 20);				// Print if server connection goes through
		status = CONNECT_SUCCESS;
	}
	return status;
}

// Communicate with server */
int communicate(void)
{
	status = 0;
	initialize_var();							// Run initialize variables function
	
	if (status == INIT_SUCCESS)
	{
		write(1, "Enter password:\n", 16);				// Prompt user to enter password
		read(0, message, MSG_SIZE);					// Read entered password
		int message_len = 0;
		for(int i = 0; message[i] != '\0'; i++)
		{
			message_len++;
		}

		ciphertext_len = encrypt(message, message_len, key, iv, ciphertext);

		send_state = send(sockt, ciphertext, ciphertext_len, 0);	// Send Password to Server
		if(send_state < 0)
		{
			write(2, "Send Failed\n", 12);				// If password send fails, print error
			status = SEND_FAIL;					// Exit the function and program
		}
		else
		{
			recv_state = recv(sockt, server_reply, RPLY_SIZE, 0);
			if(recv_state < 0)					// Receive reply from server
			{
				write(2, "Receive Failed\n", 14);		// If receive fails, print error
				status = RECV_FAIL;				// Exit the function and the program
			}
			else
			{
				int server_reply_len = 0;
				for(int i = 0; server_reply[i] != '\0'; i++)
				{
					server_reply_len++;
				}
				write(1, "Server reply:\n", 14);		// Print "Server reply:"
				write(1, server_reply, server_reply_len);	// Print reply from server
				status = COMMUNICATE_SUCCESS;
			}
		}
	}
	free(ciphertext);
	free(message);								// Free allocated memory for the message
	free(server_reply);							// Free allocated memory for the server response
	return status;
}
