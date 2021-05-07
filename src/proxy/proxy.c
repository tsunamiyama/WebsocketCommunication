/*Proxy Server*/

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <err.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <tls.h>
#include "murmur3/murmur3.h"

static void usage()
{
	extern char * __progname;
	fprintf(stderr, "usage: ./build/src/%s portnumber\n", __progname);
	exit(1);
}

static void kidhandler(int signum) {
	/* signal handler for SIGCHLD */
	waitpid(WAIT_ANY, NULL, WNOHANG);
}

void populateBloomFilter(int * filter){
    FILE *f;
	char *line = NULL;
	size_t len = 0;
	ssize_t read;
    uint32_t hash[2];
    char hashvalue[32];
    int count = 0;

    printf("Putting Blacklisted Objects into Bloomfilter\n");
	f = fopen("/mnt/c/Users/Kris/Documents/CS165AssignmentTwo/TCPSocket_iii/src/proxy/blacklist.txt","r");
	while((read = getline(&line, &len, f)) != -1){
		char *token = strtok(line,"\n");
        MurmurHash3_x86_32(token,strlen(token),1,hash);
          //printf("%s is hashed to: %08x\n", token, hash[0]);
        sprintf(hashvalue,"%u",hash[0]);
        long n =strtol(hashvalue, NULL, 16);
        long finalValue = n%303658;
        filter[finalValue] = 1;
          //printf("The hashed index is: %lu\n", finalValue);
        MurmurHash3_x86_32(token,strlen(token),2,hash);
          //printf("%s is hashed to: %08x\n", token, hash[0]);
        sprintf(hashvalue,"%u",hash[0]);
        n =strtol(hashvalue, NULL, 16);
        finalValue = n%303658;
        filter[finalValue] = 1;
          //printf("The hashed index is: %lu\n", finalValue);
        MurmurHash3_x86_32(token,strlen(token),3,hash);
          //printf("%s is hashed to: %08x\n", token, hash[0]);
        sprintf(hashvalue,"%u",hash[0]);
        n =strtol(hashvalue, NULL, 16);
        finalValue = n%303658;
        filter[finalValue] = 1;
          //printf("The hashed index is: %lu\n", finalValue);
        MurmurHash3_x86_32(token,strlen(token),4,hash);
          //printf("%s is hashed to: %08x\n", token, hash[0]);
        sprintf(hashvalue,"%u",hash[0]);
        n =strtol(hashvalue, NULL, 16);
        finalValue = n%303658;
        filter[finalValue] = 1;
          //printf("The hashed index is: %lu\n", finalValue);
        MurmurHash3_x86_32(token,strlen(token),5,hash);
          //printf("%s is hashed to: %08x\n", token, hash[0]);
        sprintf(hashvalue,"%u",hash[0]);
        n =strtol(hashvalue, NULL, 16);
        finalValue = n%303658;
        filter[finalValue] = 1;
          //printf("The hashed index is: %lu\n", finalValue);
	}
	fclose(f);
}

int checkBlacklist(char * input, int * filter){
    uint32_t hash[2];
    char hashvalue[32];

    MurmurHash3_x86_32(input,strlen(input),1,hash);
    sprintf(hashvalue,"%u",hash[0]);
    long n =strtol(hashvalue, NULL, 16);
    long finalValue = n%303658;
    if(filter[finalValue] != 1){
        return 0;
    }
    MurmurHash3_x86_32(input,strlen(input),2,hash);
    sprintf(hashvalue,"%u",hash[0]);
    n =strtol(hashvalue, NULL, 16);
    finalValue = n%303658;
    if(filter[finalValue] != 1){
        return 0;
    }
    MurmurHash3_x86_32(input,strlen(input),3,hash);
    sprintf(hashvalue,"%u",hash[0]);
    n =strtol(hashvalue, NULL, 16);
    finalValue = n%303658;
    if(filter[finalValue] != 1){
        return 0;
    }
    MurmurHash3_x86_32(input,strlen(input),4,hash);
    sprintf(hashvalue,"%u",hash[0]);
    n =strtol(hashvalue, NULL, 16);
    finalValue = n%303658;
    if(filter[finalValue] != 1){
        return 0;
    }
    MurmurHash3_x86_32(input,strlen(input),5,hash);
    sprintf(hashvalue,"%u",hash[0]);
    n =strtol(hashvalue, NULL, 16);
    finalValue = n%303658;
    if(filter[finalValue] != 1){
        return 0;
    }
    return 1;

}

char * checkCache(char * input){
    FILE *f;
	char *line = NULL;
	char *check;
	size_t len = 0;
	ssize_t read;

	f = fopen("/mnt/c/Users/Kris/Documents/CS165AssignmentTwo/TCPSocket_iii/src/proxy/localCache.txt","r");
	while((read = getline(&line, &len, f)) != -1){
		check = strstr(line, input); 
		if(check != NULL){
			char *resp = strtok(check, ":");
			resp = strtok(NULL, ":"); 
			return resp;
		} else{
		}
	}
	fclose(f);
	return NULL;
}

void writeToCache(char * input){
    FILE *f;

	f = fopen("/mnt/c/Users/Kris/Documents/CS165AssignmentTwo/TCPSocket_iii/src/proxy/localCache.txt","a");
	fprintf(f, "%s:", input);
	fclose(f);
}

void writeResponseToCache(char * input){
    FILE *f;

	f = fopen("/mnt/c/Users/Kris/Documents/CS165AssignmentTwo/TCPSocket_iii/src/proxy/localCache.txt","a");
	fprintf(f, "%s:\n", input);
	fclose(f);
}

int main(int argc, char *argv[]){
    struct tls_config *config = NULL;
	struct tls *ctx = NULL;
	struct tls *cctx = NULL;
    struct tls *ctx2 = NULL;
	struct sockaddr_in sockname, client;
	char buffer[1024], *ep;
	struct sigaction sa;
	int pd, i;
	socklen_t clientlen;
	u_short port;
	pid_t pid;
	u_long p;
	size_t maxread;
	int *bloomfilter;
    bloomfilter = (int*)malloc(303658 * sizeof(int));
    
	/*
	 * first, figure out what port we will listen on - it should
	 * be our first parameter.
	 */

	if (argc != 2)
		usage();
		errno = 0;
        p = strtoul(argv[1], &ep, 10);
        if (*argv[1] == '\0' || *ep != '\0') {
		/* parameter wasn't a number, or was empty */
		fprintf(stderr, "%s - not a number\n", argv[1]);
		usage();
	}
        if ((errno == ERANGE && p == ULONG_MAX) || (p > USHRT_MAX)) {
		/* It's a number, but it either can't fit in an unsigned
		 * long, or is too big for an unsigned short
		 */
		fprintf(stderr, "%s - value out of range\n", argv[1]);
		usage();
	}
	/* now safe to do this */
	port = p;
    printf("Proxy Port: %hu\n", port);

    /*Make the Socket*/
    memset(&sockname, 0, sizeof(sockname));
    sockname.sin_family = AF_INET;
    sockname.sin_port = htons(port);
    sockname.sin_addr.s_addr = htons(INADDR_ANY);
    pd=socket(AF_INET,SOCK_STREAM,0);
    if(pd == -1){
        err(1, "socket failed");
    }
    if(bind(pd, (struct sockaddr *) &sockname, sizeof(sockname)) == -1){
        err(1, "bind failed");
    }
    if(listen(pd,3) == -1){
        err(1, "listen failed");
    }

    sa.sa_handler = kidhandler;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = SA_RESTART;
        if(sigaction(SIGCHLD, &sa, NULL) == -1){
            err(1, "sigaction failed");
        }

	/*Fill bloomfitler with blacklist*/
    memset(bloomfilter, 0, sizeof(bloomfilter));

    if(bloomfilter == NULL){
        printf("Bloomfilter not built correctly\n");
        exit(0);
    }else{
        populateBloomFilter(bloomfilter);
        printf("Bloomfilter filled with blacklisted objects\n");
    }

    /*INITIALIZE TLS AND CONFIGURE*/
	printf("Initialize TLS\n");
	if(tls_init() != 0){
		errx(1, "tls_init");
	}

	if((config = tls_config_new()) == NULL){
		errx(1, "tls_config_new");
	}

	/*SET ROOT CERT*/
	printf("Set Root Certificate\n");
	if(tls_config_set_ca_file(config, "/mnt/c/Users/Kris/Documents/CS165AssignmentTwo/TCPSocket_iii/certificates/root.pem") != 0){
		errx(1, "tls_config_set_ca_file");
	}

	/*SERVER CERT*/
	printf("Set Server Certificate\n");
	if(tls_config_set_cert_file(config, "/mnt/c/Users/Kris/Documents/CS165AssignmentTwo/TCPSocket_iii/certificates/server.crt") == -1){
		errx(1, "tls_config_set_cert_file");
	}

	/*SERVER KEY*/
	printf("Set Server Key\n");
	if (tls_config_set_key_file(config, "/mnt/c/Users/Kris/Documents/CS165AssignmentTwo/TCPSocket_iii/certificates/server.key") == -1){
		errx(1, "tls_config_set_key");
	}

	/*SERVER CONTEXT*/
	printf("Set Server Context\n");
	if((ctx = tls_server()) == NULL){
		errx(1, "tls_server");
	}

    /*Client Context*/
    printf("Set Second Client Context\n");
    if((ctx2 = tls_client()) == NULL){
        errx(1, "tls_client");
    }

	/*CONFIG TO CONTEXT*/
	printf("Set Configure to Context\n");
	if(tls_configure(ctx, config) != 0){
		errx(1, "tls_configure: %s", tls_error(ctx));
	}

    printf("Set Configure to Context\n");
	if(tls_configure(ctx2, config) != 0){
		errx(1, "tls_configure: %s", tls_error(ctx));
	}

    printf("Proxy Up and Listening for Clients on Port %u\n", port);
    printf("-----------------------------------------------\n");
    for(;;){
        int clientsd;
        clientlen = sizeof(&client);
        clientsd = accept(pd, (struct sockaddr *)&client, &clientlen);
        if(clientsd == -1){
            err(1, "accept failed");
        }
        /*Fork to deal with each client connection*/
        pid = fork();
        if(pid == -1){
            err(1, "fork failed");
        }
        if(pid == 0){
            int ch = 0;
            char temp[1024];
            i = 0;
            ssize_t rc, msg, msgTwo, written;
            char* resp[1024];
            if(tls_accept_socket(ctx, &cctx, clientsd) == -1){
                errx(1,"tls accept failed (%s)", tls_error(ctx));
            }
            else{
                do{
                    if((i = tls_handshake(cctx)) == -1){
                        errx(1,"tls handshake failed (%s)", tls_error(cctx));
                    }
                }while(i == TLS_WANT_POLLIN || i == TLS_WANT_POLLOUT);
            }

            printf("Connected to Client\n");

            /*Read MSG from client*/
            memset(buffer, 0 ,sizeof(buffer));
            msg = -1; 
            rc = 0;
            maxread = sizeof(buffer) - 1; 
            while((msg != 0) && rc < maxread){
                msg = tls_read(cctx, buffer + rc, maxread - rc);
				if(msg == TLS_WANT_POLLIN || TLS_WANT_POLLOUT){
					continue;
				}
				if(msg < 0){
					errx(1, "tls_read failed (%s)", tls_error(ctx));
				} else{
					rc += msg;
				}
            }
            printf("Client sent: %s\n", buffer);

            /*Check the MSG with the bloomfilter*/
            printf("Checking if MSG is blacklisted\n");

            if(checkBlacklist(buffer, bloomfilter) == 1){
                printf("Client Requested Blacklisted Object, Closing Connection\n");
                memset(buffer, 0 ,sizeof(buffer));
                strncpy(buffer, "Blacklisted Object Requested, Closing Connection", sizeof(buffer));

                msgTwo = 0;
                written = 0;
                while(written < strlen(buffer)){
                    msgTwo = tls_write(cctx, buffer + written, strlen(buffer) - written);
                    if(msgTwo == TLS_WANT_POLLIN || msgTwo == TLS_WANT_POLLOUT){
                        continue;
                    }
                    if(msgTwo<0){
                        err(1, "tls_write failed (%s)", tls_error(cctx));
                    }else{
                        written += msgTwo;
                    }
                    i = 0;
                    do{
                        i = tls_close(cctx);
                    }while(i == TLS_WANT_POLLIN || i == TLS_WANT_POLLOUT);
                }
                printf("-----------------------------------------------\n");
                break;
            } 
            else{
                printf("Client Requested Object Not on Blacklist\n");
            }
            if(checkCache(buffer) != NULL){
                printf("Obj Found in Local Cache , Sending Stored Answer\n");
                strncpy(buffer, checkCache(buffer), sizeof(buffer));

                msgTwo = 0;
                written = 0;
                while(written < strlen(buffer)){
                    msgTwo = tls_write(cctx, buffer + written, strlen(buffer) - written);
                    if(msgTwo == TLS_WANT_POLLIN || msgTwo == TLS_WANT_POLLOUT){
                        continue;
                    }
                    if(msgTwo<0){
                        err(1, "tls_write failed (%s)", tls_error(cctx));
                    }else{
                        written += msgTwo;
                    }
                    i = 0;
                    do{
                        i = tls_close(cctx);
                    }while(i == TLS_WANT_POLLIN || i == TLS_WANT_POLLOUT);
                }
                printf("Response Sent to Client\n");
                ch = 1;
            }else{
                printf("Obj Not Found in Local Cache, Adding...\n");
                writeToCache(buffer);
            }

            if(ch == 0){
                /*Create Socket for Server*/
                int serversd = 0;
                struct sockaddr_in server;
                serversd = socket(AF_INET, SOCK_STREAM, 0);
                if(serversd < 0){
                    err(1,"Server Socket not Created\n");
                }
                printf("Server Socket Created\n");
                    
                memset(&server, 0, sizeof(server));
                server.sin_family = AF_INET;
                server.sin_port = htons(9999);
                server.sin_addr.s_addr = inet_addr("127.0.0.1");
                if (server.sin_addr.s_addr == INADDR_NONE) {
                    fprintf(stderr, "Invalid IP address %s\n", argv[3]);
                    usage();
                }
                if(connect(serversd, (struct sockaddr *)&server, sizeof(server)) == -1){
                    err(1,"Server Connection Not Established\n");
                }
                printf("Server Socket Connected\n");

                printf("TLS Connect Server Socket\n");
                if(tls_connect_socket(ctx2, serversd, "localhost") == -1){
                    err(1, "tls connection failedx (%s)", tls_error(ctx2));
                }
                do{
                    printf("TLS Handshake\n");
                    if((i = tls_handshake(ctx2)) == -1){
                        errx(1, "tls handshake failed (%s)", tls_error(ctx2));
                    }
                }while(i == TLS_WANT_POLLIN || i == TLS_WANT_POLLOUT);

                printf("TLS set up correctly, handshake done\n");

                /*Send MSG to Server*/
                msgTwo = 0;
                written = 0;
                while(written < strlen(buffer)){
                    msgTwo = tls_write(ctx2, buffer + written, strlen(buffer) - written);
                    if(msgTwo == TLS_WANT_POLLIN || msgTwo == TLS_WANT_POLLOUT){
                        continue;
                    }
                    if(msgTwo<0){
                        err(1, "tls_write failed (%s)", tls_error(ctx2));
                    }else{
                        written += msgTwo;
                    }
                    i = 0;
                    do{
                        i = tls_close(ctx2);
                    }while(i == TLS_WANT_POLLIN || i == TLS_WANT_POLLOUT);
                }
                printf("Client MSG Sent to Server: %s\n", buffer);
                memset(buffer, 0 ,sizeof(buffer));

                /*Read Response from Server*/
                msg = -1;
                rc = 0;
                maxread = sizeof(buffer) - 1;
                while((msg != 0) && rc < maxread){
                    msg = tls_read(ctx2, buffer + rc, maxread - rc);
                    if(msg == TLS_WANT_POLLIN || TLS_WANT_POLLOUT){
                        continue;
                    }
                    if(msg < 0){
                        errx(1, "tls_read failed (%s)", tls_error(ctx2));
                    } else{
                        rc+= msg;
                    }
                }
                printf("Server Response: %s\n", buffer);
                printf("Adding to Local Cache\n");
                
                writeResponseToCache(buffer);

                /*Send Server Response to Client*/
                msgTwo = 0;
                written = 0;
                while(written < strlen(buffer)){
                    msgTwo = tls_write(cctx, buffer + written, strlen(buffer) - written);
                    if(msgTwo == TLS_WANT_POLLIN || msgTwo == TLS_WANT_POLLOUT){
                        continue;
                    }
                    if(msgTwo<0){
                        err(1, "tls_write failed (%s)", tls_error(cctx));
                    }else{
                        written += msgTwo;
                    }
                    i = 0;
                    do{
                        i = tls_close(cctx);
                    }while(i == TLS_WANT_POLLIN || i == TLS_WANT_POLLOUT);
                }
                printf("Response Sent to Client\n");

                close(serversd);
            }
            memset(buffer, 0 ,sizeof(buffer));
            printf("-----------------------------------------------\n");
            exit(0);
        }
        close(clientsd);
    }
    //free(bloomfilter);
}
