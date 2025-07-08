/*####################################################
##                                                  ##
##              HTTPS Server in C                   ##
##              By William Hocking                  ##
##                                                  ##
####################################################*/

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <stdio.h>
#include <stdlib.h>


#include "http.h"

// Other macros
#define DEFAULT_PORT 4433
#define BACKLOG_QUEUE 10

int main(int argc, char **argv) {
	int serverSocket, clientSocket;
	
	struct sockaddr_in serverAddr, clientAddr;
	socklen_t clientLen = sizeof(clientAddr);
	char request[MAX_REQUEST_SIZE];

	serverSocket = socket(AF_INET, SOCK_STREAM, 0);
	if (serverSocket < 0) {
		perror("Failed to create socket.\n");
		exit(EXIT_FAILURE);
	}

	int opt = 1;
	setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));	

	serverAddr.sin_family = AF_INET;
	serverAddr.sin_addr.s_addr = INADDR_ANY;
	serverAddr.sin_port = htons(DEFAULT_PORT);

	if (bind(serverSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0) {
		perror("Bind Failed\n");
		exit(EXIT_FAILURE);
	}
	
	if (listen(serverSocket, BACKLOG_QUEUE) < 0) {
		perror("Listen failed.\n");
		exit(EXIT_FAILURE);
	}

	printf("Server running on port %d\n", DEFAULT_PORT);
	
	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();
	
	SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
	if (!ctx) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	// Ensure certificate is read. Exit on failure.
	if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0) {
    		ERR_print_errors_fp(stderr);
    		exit(EXIT_FAILURE);
	}
	// Ensure private key is read. Exit on failure.
	if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0) {
    		ERR_print_errors_fp(stderr);
   		exit(EXIT_FAILURE);
	}

	while (1) {
		clientSocket = accept(serverSocket, (struct sockaddr *)&clientAddr, &clientLen);
		if (clientSocket < 0) {
			perror("Accept failed.\n");
			continue;
		}
			

		SSL *ssl = SSL_new(ctx);
		SSL_set_fd(ssl, clientSocket);
		
		if (SSL_accept(ssl) <= 0) {
			ERR_print_errors_fp(stderr);
			SSL_free(ssl);
			close(clientSocket);
			continue;
		}

		ssize_t bytesRead = SSL_read(ssl, request, sizeof(request) - 1);
		if (bytesRead < 0) {
			perror("SSL Read failed.\n");
			SSL_free(ssl);
			close(clientSocket);
			continue;
		}
		request[bytesRead] = '\0';
		HandleRequest(ssl, request);
		
		SSL_shutdown(ssl);
		SSL_free(ssl);
		close(clientSocket);
	}
	
	SSL_CTX_free(ctx);
	EVP_cleanup();
	return 0;
}
