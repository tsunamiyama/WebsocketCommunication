/*Client Code*/

#include <arpa/inet.h>

#include <netinet/in.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <err.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <tls.h>
#include <time.h>
#include "murmur3/murmur3.h"


static void usage()
{
	extern char * __progname;
	fprintf(stderr, "usage: %s ipaddress\n", __progname);
	exit(1);
}

char* getFileInput(){
	FILE *f;
	char *line = NULL;
	size_t len = 0;
	ssize_t read;
	int count, lineNum;

	/*Determine Randomly Which Line of File to Send*/
	lineNum = (rand() % (26 - 1 + 1)) + 1;
	count = 1;
	f = fopen("/mnt/c/Users/Kris/Documents/CS165AssignmentTwo/TCPSocket_iii/src/client/input.txt","r");
	while((read = getline(&line, &len, f)) != -1){
		if(count == lineNum){
			char *token = strtok(line,"\n");
			return token;
			break;
		} else{
			count++;
		}
	}
	fclose(f);
	return line;
}

char * rendezvousHash(char * input){
	/*Assuming 5 Different Proxies*/
	long biggestHash;
	char * port;

	char portOne[1024] = "Port1";
		char hashvalue1[32];
		strcat(portOne, input);
		uint32_t hash1[2];
		MurmurHash3_x86_32(portOne,strlen(portOne),1,hash1);
		sprintf(hashvalue1,"%u",hash1[0]);
        long n1 = strtol(hashvalue1, NULL, 16);

	char portTwo[1024] = "Port2";
		char hashvalue2[32];
		strcat(portTwo, input);
		uint32_t hash2[2];
		MurmurHash3_x86_32(portTwo,strlen(portTwo),1,hash2);
		sprintf(hashvalue2,"%u",hash2[0]);
        long n2 = strtol(hashvalue2, NULL, 16);

	char portThree[1024] = "Port3";
		char hashvalue3[32];
		strcat(portThree, input);
		uint32_t hash3[2];
		MurmurHash3_x86_32(portThree,strlen(portThree),1,hash3);
		sprintf(hashvalue3,"%u",hash3[0]);
        long n3 = strtol(hashvalue3, NULL, 16);

	char portFour[1024] = "Port4";
		char hashvalue4[32];
		strcat(portFour, input);
		uint32_t hash4[2];
		MurmurHash3_x86_32(portFour,strlen(portFour),1,hash4);
		sprintf(hashvalue4,"%u",hash4[0]);
        long n4 = strtol(hashvalue4, NULL, 16);

	char portFive[1024] = "Port5";
		char hashvalue5[32];
		strcat(portFive, input);
		uint32_t hash5[2];
		MurmurHash3_x86_32(portFive,strlen(portFive),1,hash5);
		sprintf(hashvalue5,"%u",hash5[0]);
        long n5 = strtol(hashvalue5, NULL, 16);

	biggestHash = n1;
	port = "9998";

	if(biggestHash < n2){
		biggestHash = n2;
		port = "9997";
	}
	if(biggestHash < n3){
		biggestHash = n3;
		port = "9996";
	}
	if(biggestHash < n4){
		biggestHash = n4;
		port = "9995";
	}
	if(biggestHash < n5){
		biggestHash = n5;
		port = "9994";
	}

	printf("Will Set Up Connection to Proxy on Port %s\n", port);
	return port;

}

int main(int argc, char *argv[])
{
	struct tls_config *config = NULL;
	struct tls *ctx = NULL;
	struct sockaddr_in server_sa;
	char buffer[1024], *ep;
	size_t maxread;
	ssize_t msg, written;
	u_short port;
	u_long p;
	int sd, i;

	srand(time(0));
	if (argc != 2){
		usage();
	}

	/* the message we send the server */
	memset(buffer, 0 ,sizeof(buffer));
	strncpy(buffer, getFileInput(), sizeof(buffer));
	printf("Message Being Requested: %s\n", buffer);

	/* now safe to do this */
	p = strtoul(rendezvousHash(buffer), &ep, 10);
	port = p;

	/*
	 * first set up "server_sa" to be the location of the server
	 */
	memset(&server_sa, 0, sizeof(server_sa));
	server_sa.sin_family = AF_INET;
	server_sa.sin_port = htons(port);
	server_sa.sin_addr.s_addr = inet_addr(argv[1]);
	if (server_sa.sin_addr.s_addr == INADDR_NONE) {
		fprintf(stderr, "Invalid IP address %s\n", argv[1]);
		usage();
	}

	/* ok now get a socket. we don't care where... */
	if ((sd=socket(AF_INET,SOCK_STREAM,0)) == -1){
		err(1, "socket failed");
	}

	/*INITIALIZE TLS AND CONFIGURE*/
	printf("Initialize TLS\n");
	if(tls_init() != 0){
		err(1, "tls_init");
	}

	if((config = tls_config_new()) == NULL){
		err(1, "tls_config_new");
	}

	/*SET ROOT CERT*/
	printf("Set Root Certificate\n");
	if(tls_config_set_ca_file(config, "/mnt/c/Users/Kris/Documents/CS165AssignmentTwo/TCPSocket_iii/certificates/root.pem") != 0){
		err(1, "tls_config_set_ca_file");
	}

	/*CLIENT CONTEXT*/
	printf("Set Client Context\n");
	if((ctx = tls_client()) == NULL){
		err(1, "tls_client");
	}

	/*CONFIG to CONTEXT*/
	printf("Set Configure to Context\n");
	if(tls_configure(ctx, config) != 0){
		err(1, "tls_configure: %s", tls_error(ctx));
	}

	/* connect the socket to the server described in "server_sa" */
	if (connect(sd, (struct sockaddr *)&server_sa, sizeof(server_sa)) == -1){
		err(1, "connect failed");
	}

	printf("Socket Connected\n");

	/*TLS CONNECT*/
	printf("TLS Connect Socket\n");
	if (tls_connect_socket(ctx, sd, "localhost") == -1) {
		errx(1, "tls connection failed (%s)", tls_error(ctx));
	}
	do {
		printf("TLS Handshake\n");
		if ((i = tls_handshake(ctx)) == -1){
			errx(1, "tls handshake failed (%s)", tls_error(ctx));
		}
	} while (i == TLS_WANT_POLLIN || i == TLS_WANT_POLLOUT);

	//printf("TLS Peer Certificate Hash\n");
	/*if (strcmp(argv[2], tls_peer_cert_hash(ctx)) != 0)
		errx(1, "Peer certificate is not %s", argv[3]); */

	printf("TLS set up correctly, handshake done\n");

	/*
	 * finally, we are connected. find out what magnificent wisdom
	 * our server is going to send to us - since we really don't know
	 * how much data the server could send to us, we have decided
	 * we'll stop reading when either our buffer is full, or when
	 * we get an end of file condition from the read when we read
	 * 0 bytes - which means that we pretty much assume the server
	 * is going to send us an entire message, then close the connection
	 * to us, so that we see an end-of-file condition on the read.
	 *
	 * we also make sure we handle EINTR in case we got interrupted
	 * by a signal.
	 */
	msg = 0;
	written = 0;
	while(written < strlen(buffer)){
		msg = tls_write(ctx, buffer + written, strlen(buffer) - written);
		if(msg == TLS_WANT_POLLIN || msg == TLS_WANT_POLLOUT){
			continue;
		}
		if(msg<0){
			errx(1, "tls_write failed (%s)", tls_error(ctx));
		}else{
			written += msg;
		}
		i = 0;
		do {
			i = tls_close(ctx);
		} while(i == TLS_WANT_POLLIN || i == TLS_WANT_POLLOUT);
	}
	printf("MSG SENT: %s\n", buffer);

	/*Read Response from Proxy*/
	memset(buffer, 0, sizeof(buffer));
	msg = -1;
	written = 0;
	maxread = sizeof(buffer) - 1;
	while((msg != 0) && written < maxread){
		msg = tls_read(ctx, buffer + written, maxread - written);
		if(msg == TLS_WANT_POLLIN || TLS_WANT_POLLOUT){
			continue;
		}
		if(msg < 0){
			errx(1, "tls_read failed (%s)", tls_error(ctx));
		}else{
			written += msg;
		}
	}
	printf("Response from Proxy: %s\n", buffer);
	close(sd);
	return(0);
}
