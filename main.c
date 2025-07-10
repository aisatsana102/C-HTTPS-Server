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
#include <string.h> 
#include "http.h"

#define DEFAULT_PORT 4433
#define BACKLOG_QUEUE 10

int main(int argc, char **argv) {
    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket < 0) {
        perror("Failed to create socket");
        exit(EXIT_FAILURE);
    }

    int opt = 1;
    if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt failed");
        close(serverSocket);
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in serverAddr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = INADDR_ANY,
        .sin_port = htons(DEFAULT_PORT)
    };

    if (bind(serverSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0) {
        perror("Bind failed");
        close(serverSocket);
        exit(EXIT_FAILURE);
    }

    if (listen(serverSocket, BACKLOG_QUEUE) < 0) {
        perror("Listen failed");
        close(serverSocket);
        exit(EXIT_FAILURE);
    }

    printf("Server running on port %d\n", DEFAULT_PORT);

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        close(serverSocket);
        exit(EXIT_FAILURE);
    }

    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);

    if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        close(serverSocket);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        close(serverSocket);
        exit(EXIT_FAILURE);
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Certificate and private key don't match\n");
        SSL_CTX_free(ctx);
        close(serverSocket);
        exit(EXIT_FAILURE);
    }

    while (1) {
        struct sockaddr_in clientAddr;
        socklen_t clientLen = sizeof(clientAddr);
        int clientSocket = accept(serverSocket, (struct sockaddr *)&clientAddr, &clientLen);
        
        if (clientSocket < 0) {
            perror("Accept failed");
            continue;
        }

        char clientIP[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &clientAddr.sin_addr, clientIP, INET_ADDRSTRLEN);
        printf("Connection from %s\n", clientIP);

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, clientSocket);

        int ssl_accept_ret = SSL_accept(ssl);
        if (ssl_accept_ret <= 0) {
            int ssl_err = SSL_get_error(ssl, ssl_accept_ret);
            fprintf(stderr, "SSL handshake failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
            
            switch(ssl_err) {
                case SSL_ERROR_SSL:
                    fprintf(stderr, "SSL protocol error\n");
                    break;
                case SSL_ERROR_SYSCALL:
                    perror("SSL syscall error");
                    break;
                case SSL_ERROR_ZERO_RETURN:
                    fprintf(stderr, "SSL connection closed\n");
                    break;
                default:
                    fprintf(stderr, "Unknown SSL error\n");
            }
            
            SSL_free(ssl);
            close(clientSocket);
            continue;
        }

        HTTPRequest req;
        do {
            memset(&req, 0, sizeof(HTTPRequest));
            char request[MAX_REQUEST_SIZE];
            
            ssize_t bytesRead = SSL_read(ssl, request, sizeof(request) - 1);
            if (bytesRead <= 0) {
                int ssl_err = SSL_get_error(ssl, bytesRead);
                if (ssl_err != SSL_ERROR_ZERO_RETURN) {
                    fprintf(stderr, "SSL read error: %s\n", ERR_error_string(ERR_get_error(), NULL));
                }
                break;
            }

            request[bytesRead] = '\0';
            HandleRequest(ssl, request, &req);
        } while (req.keepAlive);

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(clientSocket);
    }

    SSL_CTX_free(ctx);
    EVP_cleanup();
    close(serverSocket);
    return 0;
}
