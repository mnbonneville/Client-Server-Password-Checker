#ifndef _CLIENT_H
#define _CLIENT_H

typedef unsigned char uint8_t;

/* Function Protocols */
int initialize_var(void);
int create_socket(void);
int connect_server(void);
int communicate(void);

#endif //_CLIENT_H
