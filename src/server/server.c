/*Server Code*/

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>

#include <err.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <tls.h>

static void usage()
{
	extern char * __progname;
	fprintf(stderr, "usage: %s portnumber\n", __progname);
	exit(1);
}

static void kidhandler(int signum) {
	/* signal handler for SIGCHLD */
	waitpid(WAIT_ANY, NULL, WNOHANG);
}

char * findResponse(char *input){
	FILE *f;
	char *line = NULL;
	char *check;
	char *error = "ERROR: MATCHING OUTPUT NOT FOUND!";
	size_t len = 0;
	ssize_t read;

	f = fopen("/mnt/c/Users/Kris/Documents/CS165AssignmentTwo/TCPSocket_iii/src/server/output.txt","r");
	while((read = getline(&line, &len, f)) != -1){
		check = strstr(line, input); 
		if(check != NULL){
			char *resp = strtok(check, ":");
			resp = strtok(NULL, "\n"); 
			return resp;
		} else{
		}
	}
	fclose(f);
	return error;
}

int main(int argc,  char *argv[])
{
	struct tls_config *config = NULL;
	struct tls *ctx = NULL;
	struct tls *cctx = NULL;
	struct sockaddr_in sockname, client;
	char buffer[1024], *ep, resp[1024];
	struct sigaction sa;
	int sd, i;
	socklen_t clientlen;
	u_short port;
	pid_t pid;
	u_long p;
	size_t maxread;

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

	/* Making sure arrays are empty before using them */
	memset(buffer, 0, sizeof(buffer));
	memset(resp, 0, sizeof(resp));

	memset(&sockname, 0, sizeof(sockname));
	sockname.sin_family = AF_INET;
	sockname.sin_port = htons(port);
	sockname.sin_addr.s_addr = htonl(INADDR_ANY);
	sd=socket(AF_INET,SOCK_STREAM,0);
	if ( sd == -1)
		err(1, "socket failed");

	if (bind(sd, (struct sockaddr *) &sockname, sizeof(sockname)) == -1)
		err(1, "bind failed");

	if (listen(sd,3) == -1)
		err(1, "listen failed");

	/*
	 * we're now bound, and listening for connections on "sd" -
	 * each call to "accept" will return us a descriptor talking to
	 * a connected client
	 */


	/*
	 * first, let's make sure we can have children without leaving
	 * zombies around when they die - we can do this by catching
	 * SIGCHLD.
	 */
	sa.sa_handler = kidhandler;
        sigemptyset(&sa.sa_mask);
	/*
	 * we want to allow system calls like accept to be restarted if they
	 * get interrupted by a SIGCHLD
	 */
        sa.sa_flags = SA_RESTART;
        if (sigaction(SIGCHLD, &sa, NULL) == -1)
                err(1, "sigaction failed");

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

	/*CONFIG TO CONTEXT*/
	printf("Set Configure to Context\n");
	if(tls_configure(ctx, config) != 0){
		errx(1, "tls_configure: %s", tls_error(ctx));
	}

	/*
	 * finally - the main loop.  accept connections and deal with 'em
	 */
	printf("Server up and listening for connections on port %u\n", port);
	printf("-----------------------------------------------\n");
	for(;;) {
		int clientsd;
		clientlen = sizeof(&client);
		clientsd = accept(sd, (struct sockaddr *)&client, &clientlen);
		if (clientsd == -1)
			err(1, "accept failed");
		/*
		 * We fork child to deal with each connection, this way more
		 * than one client can connect to us and get served at any one
		 * time.
		 */

		pid = fork();
		if (pid == -1)
		     err(1, "fork failed");

		if(pid == 0) {
			i = 0;
			ssize_t rc, msg;
			if (tls_accept_socket(ctx, &cctx, clientsd) == -1)
				errx(1, "tls accept failed (%s)", tls_error(ctx));
			else {
				do {
					if ((i = tls_handshake(cctx)) == -1)
						errx(1, "tls handshake failed (%s)", tls_error(cctx));
				} while(i == TLS_WANT_POLLIN || i == TLS_WANT_POLLOUT);
			}
			/*
			 * write the message to the client, being sure to
			 * handle a short write, or being interrupted by
			 * a signal before we could write anything.
			 */

			 /*Get MSG from proxy*/
			printf("Getting MSG\n");
			memset(buffer, 0 , sizeof(buffer));
			memset(resp, 0, sizeof(resp));
			msg = -1;
			rc = 0;
			maxread = sizeof(buffer) - 1; /* leave room for a 0 byte */
			while((msg != 0) && rc < maxread){
				//printf("%s\n", buffer);
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
			strncpy(resp, findResponse(buffer), sizeof(resp));

			msg = 0;
			rc = 0;
			while(rc < strlen(resp)){
				msg = tls_write(cctx, resp + rc, strlen(resp) - rc);
				if(msg == TLS_WANT_POLLIN || msg == TLS_WANT_POLLOUT){
					continue;
				}
				if(msg<0){
					err(1, "tls_write failed (%s)", tls_error(cctx));
				}else{
					rc += msg;
				}
				i = 0;
				do{
					i = tls_close(cctx);
				}while(i == TLS_WANT_POLLIN || i == TLS_WANT_POLLOUT);
			}
			printf("Sending MSG to Proxy: %s\n", resp);
			memset(buffer, 0 ,sizeof(buffer));

			printf("-----------------------------------------------\n");

			close(clientsd);
			exit(0);
		}
		close(clientsd);
	}
}
