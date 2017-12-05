#ifndef _SERVER_H
#define _SERVER_H

typedef unsigned char uint8_t;

/* Function Protocols */
int initval(void);
int create_socket(void);
int bind_listen(void);
int accept_client(void);
int readf(void);
void *connection_handler(void *);

#endif //_SERVER_H
