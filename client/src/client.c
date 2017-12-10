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
#include <openssl/sha.h>

// Define Size and Error Variables */
#define VALID_SIZE		16
#define INVALID_SIZE		18
#define MSG_SIZE		50
#define RPLY_SIZE		20
#define HASH_SIZE		256
#define TOTAL			512
#define INIT_FAIL		0x03
#define MSG_MEM_ALLOC_FAIL	0x07
#define SRV_MEM_ALLOC_FAIL	0x11
#define INIT_SUCCESS		0x15
#define CONNECT_SUCCESS		0x19
#define CONNECT_FAIL		0x23
#define SOCK_CREATE_FAIL	0x27
#define SOCK_CREATE_SUCCESS	0x31
#define SEND_FAIL		0x35
#define RECV_FAIL		0x39
#define COMMUNICATE_SUCCESS	0x43
#define CT_FAIL			0x47
#define HASH_ALLOC_FAIL		0x51
#define TOTAL_FAIL		0x55
#define TEST_FAIL		0x59
#define SEC_POL_PASS		0x63

extern int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext);
extern int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext);
extern void handleErrors(void);
extern unsigned char* hash_data(const char* data);
extern int pass_pol(const char *s);
extern int brute_5(int i, char val);

// Declaration of Global Variables and Initialization of pointers to NULL */
int sockt = 0;									// Socket used to communicate with the server
struct sockaddr_in server;							// To hold server connection information
uint8_t *message = NULL;							// Password from input
char *server_reply = NULL;							// Reply from server
int send_state = 0;
int recv_state = 0;
int sendtotal_len = 0;
int status = 0;
uint8_t *key = NULL;
uint8_t *iv = NULL;
uint8_t *ciphertext = NULL;
uint8_t *hashedpass = NULL;
uint8_t *sendtotal = NULL;
int ciphertext_len;
uint8_t *test = NULL;


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
				test = (uint8_t *)calloc(HASH_SIZE,sizeof(uint8_t));
				if(test < 0)
				{
					status = TEST_FAIL;
				}
				else
				{
					hashedpass = (uint8_t *)calloc(HASH_SIZE,sizeof(uint8_t));
					if(hashedpass < 0)
					{
						status = HASH_ALLOC_FAIL;
					}
					else
					{	
						sendtotal = (uint8_t *)calloc(TOTAL,sizeof(uint8_t));
				
						if(sendtotal < 0)
						{
							status = TOTAL_FAIL;
						}
						else
						{
							status = INIT_SUCCESS;
							key = (uint8_t *)"01234567890123456789012345678901";
							iv = (uint8_t *)"0123456789012345";
						}
					}
				}
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
	int brute = 0;
	int done = 0;
	char v;
	do
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

			status = pass_pol((const char *)message);

			if(status == SEC_POL_PASS)
			{
				ciphertext_len = encrypt(message, message_len, key, iv, ciphertext);
				message[strcspn((const char *)message, "\n")] = 0;
				hashedpass = hash_data((const char *)message);
				memcpy(test,hashedpass,64);
				strncpy((char *)sendtotal,(const char *)ciphertext,ciphertext_len);
				strncat((char *)sendtotal,":",1);
				strncat((char *)sendtotal,(const char *)test,64);
				strncat((char *)sendtotal,"\0",1);
		
				for(int i = 0; sendtotal[i] != '\0'; i++)
				{
					sendtotal_len++;
				}
		
				send_state = send(sockt, sendtotal, sendtotal_len, 0);	// Send Password to Server
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
						if(server_reply_len == VALID_SIZE)
						{
							done = 5;
							v = 'v';
							brute = brute_5(done,v);
						}
						else
						{
							done++;
							v = 'i';
							brute = brute_5(done,v);
						}
						status = COMMUNICATE_SUCCESS;
					}
				}
			}
			else
			{
				done++;
				v = 'i';
				brute = brute_5(done,v);
			}
		}
	free(ciphertext);
	free(message);								// Free allocated memory for the message
	free(server_reply);							// Free allocated memory for the server response
	free(test);
	//free(hashedpass);							// When uncommented, error saying invalid address and aborted core
	free(sendtotal);
	} while (brute == SEC_POL_PASS);

	return status;
}
