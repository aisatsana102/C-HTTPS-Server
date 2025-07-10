# C HTTPS Server by William Hocking 

A lightweight HTTPS server written in C, leveraging OpenSSL for secure TLS connections. This project serves static HTML content and is ideal for educational purposes or as a foundational component for more complex web servers.

## Features
- **HTTP/1.1
- **HTTPS Support**: Secure communication using TLS via OpenSSL.
- **Static File Serving**: Serves files from the `www/` directory.
- **Modular Codebase**: Separation of concerns with distinct modules for HTTP handling and server logic.
- **Customizable**: Easily extendable to support additional HTTP methods or dynamic content.

## Prerequisites

- **Operating System**: Unix-like systems (e.g., Linux, macOS).
- **Compiler**: GCC or compatible C compiler.
- **Libraries**:
  - OpenSSL (version 3.x recommended)

Ensure OpenSSL is installed and accessible. On macOS with Homebrew:

```sh
brew install openssl@3
```

## Building the Server

A `Makefile` is provided for convenience. To build the server:

```sh
make
```

This compiles the source files and produces an executable named `server`.

## Running the Server

After building, run the server with:

```sh
./server
```

By default, the server listens on port 443 and serves content from the `www/` directory.

## Directory Structure

```
C-HTTPS-Server/
├── Makefile        # Build configuration
├── README.md       # Project documentation
├── extensions.h    # Header for file extension handling
├── http.c          # HTTP request handling
├── http.h          # HTTP module header
├── main.c          # Entry point and server setup
├── www/            # Directory containing static HTML files
```

## Customization

- **Port Configuration**: Modify `main.c` to change the listening port.
- **Document Root**: Change the path in `main.c` to serve files from a different directory.
- **TLS Certificates**: Update the paths to your SSL certificate and key in the source code as needed.

## Security Considerations

- **Self-Signed Certificates**: For testing purposes, you can generate self-signed certificates. For production, obtain certificates from a trusted Certificate Authority.
- **Input Validation**: Ensure proper validation of HTTP requests to prevent vulnerabilities.
- **Error Handling**: Implement comprehensive error handling for robustness.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgments
- [ankushagarwal/nweb](https://github.com/ankushagarwal/nweb) — A minimalist web server in C that served as inspiration.
- [Wikipedia: HTTP](https://en.wikipedia.org/wiki/HTTP) — Overview of the HTTP protocol.
- [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110) — HTTP/1.1 semantics specification from the IETF.
- [RFC 9112](https://www.rfc-editor.org/rfc/rfc9112) - HTTP/1.1. 
and many others!
