/*####################################################
##                                                  ##
##                                                  ##
####################################################*/
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

// HTTP Constants
#define HTTP_OK                 200
#define HTTP_BAD_REQUEST        400
#define HTTP_NOT_FOUND          404
#define HTTP_METHOD_NOT_ALLOWED 405
#define HTTP_INTERNAL_ERROR     500

// HTTP Message Macros
#define HTTP_MSG_OK             "OK"
#define HTTP_MSG_BAD_REQUEST    "Bad Request"
#define HTTP_MSG_NOT_FOUND      "Not Found"
#define HTTP_MSG_METHOD_NOT_ALLOWED "Method Not Allowed"
#define HTTP_MSG_INTERNAL_ERROR "Internal Server Error"

// Max length macros
#define MAX_REQUEST_SIZE 8192
#define MAX_PATH_LEN 1024

#define DEFAULT_PORT 4433
#define BACKLOG_QUEUE 10

const char* GetHTTPSStatusMessage(int status) {
	switch (status) {
		case HTTP_OK: return HTTP_MSG_OK;
		case HTTP_BAD_REQUEST: return HTTP_MSG_BAD_REQUEST;
		case HTTP_NOT_FOUND: return HTTP_MSG_NOT_FOUND;
		case HTTP_METHOD_NOT_ALLOWED: return HTTP_MSG_METHOD_NOT_ALLOWED;
		case HTTP_INTERNAL_ERROR: return HTTP_MSG_INTERNAL_ERROR;
		default: return "Unknown status.";
	}
}

void HandleGet(SSL *ssl, const char *path) { 
	if (strcmp(path, "/") == 0) {
		const char response[] = 
		"HTTP/1.1 200 OK\r\n"
		"Content-Type: text/plain\r\n"
		"\r\n";
		SSL_write(ssl, response, strlen(response));
		printf("%s\n", response);
	} else {
		const char *notFound = 
		"HTTP/1.1 404 Not Found\r\n"
		"Content-Length: 0\r\n"
		"\r\n"
		"404 Not Found";
		SSL_write(ssl, notFound, strlen(notFound));
	}
}


void HandleRequest(SSL *ssl, const char *request) {
	char method[16], path[MAX_PATH_LEN], body[MAX_REQUEST_SIZE] = {0};
	sscanf(request, "%15s %1023s", method, path);
	const char *bodyStart = strstr(request, "\r\n\r\n");
	if (bodyStart) { strlcpy(body, bodyStart + 4, sizeof(body)); }
	
	if (strcmp(method, "GET") == 0) {  HandleGet(ssl, path); }
	else if (strcmp(method, "PUT") == 0) { }
	else if (strcmp(method, "POST") == 0) { }
	else if (strcmp(path, "/echo") == 0) { HandleEcho(ssl, body); }
	else { return; }
}



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

	if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0) {
    		ERR_print_errors_fp(stderr);
    		exit(EXIT_FAILURE);
	}

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
