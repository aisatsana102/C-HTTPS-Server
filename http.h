/*####################
##                  ##
####################*/
#pragma once
#ifndef HTTP_H
#define HTTP_H
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
#define MAX_HEADERS 50
#define MAX_HEADER_NAME 256
#define MAX_HEADER_VALUE 1024
#define MAX_METHOD_LEN 16
#define MAX_VERSION_LEN 16

#define MAX_REQUEST_SIZE 8192
#define MAX_PATH_LEN 1024

typedef struct {
    char name[MAX_HEADER_NAME];
    char value[MAX_HEADER_VALUE];
} HTTPHeader;

typedef struct {
    char method[MAX_METHOD_LEN];
    char path[MAX_PATH_LEN];
    char httpVersion[MAX_VERSION_LEN];
    HTTPHeader headers[MAX_HEADERS];
    int headerCount;
    char *body;
    size_t bodyLength;
} HTTPRequest;

/* Public HTTP Functions  */
const char *GetMimeType(const char *path);
void HandleGet(SSL *ssl, const char *path);
int ParseRequestLine(const char *request, HTTPRequest *req);
void HandleRequest(SSL *ssl, const char *rawRequest);
const char *GetHTTPStatusMessage(int code);
void WriteError(SSL *ssl, int statusCode);

#endif
