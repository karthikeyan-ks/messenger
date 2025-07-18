//
// Created by karthi on 15/07/25.
//
#include "platform.h"
#include <sys/epoll.h>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <sstream>
#include <unordered_set>
#include <vector>
#include <string>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <unordered_map>
#include <arpa/inet.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/sha.h>
#include <csignal>

using namespace std;
static unordered_map<int, bool> handshakeDone;
volatile sig_atomic_t keep_running = 1;

void inthandler(int) {
    cout << "Server shutting down..." << endl;
    keep_running = 0;
}

string base64Encode(const unsigned char* input, int length) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);  // Disable newline
    BIO_write(bio, input, length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);

    string result(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);
    return result;
}

string generateAcceptKey(const string& key) {
    string magic = key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1(reinterpret_cast<const unsigned char*>(magic.c_str()), magic.size(), hash);
    return base64Encode(hash, SHA_DIGEST_LENGTH);
}

string decodeWebSocketFrame(const char *buffer, int length) {
    if (length < 2) return "";

    const unsigned char *data = reinterpret_cast<const unsigned char *>(buffer);
    bool isMasked = (data[1] & 0x80) != 0;
    int payloadLen = data[1] & 0x7F;
    int offset = 2;

    if (payloadLen == 126) {
        payloadLen = (data[2] << 8) | data[3];
        offset += 2;
    } else if (payloadLen == 127) {
        std::cerr << "Payload too large, not supported." << std::endl;
        return "";
    }

    unsigned char mask[4] = {0};
    if (isMasked) {
        for (int i = 0; i < 4; i++) {
            mask[i] = data[offset + i];
        }
        offset += 4;
    }

    string decoded;
    for (int i = 0; i < payloadLen; i++) {
        char byte = data[offset + i];
        if (isMasked) {
            byte ^= mask[i % 4];
        }
        decoded += byte;
    }

    return decoded;
}

vector<char> encodeWebSocketFrame(const string &message) {
    vector<char> frame;
    frame.push_back(0x81); // FIN + Text frame

    size_t len = message.size();
    if (len <= 125) {
        frame.push_back(static_cast<char>(len));
    } else if (len <= 65535) {
        frame.push_back(126);
        frame.push_back((len >> 8) & 0xFF);
        frame.push_back(len & 0xFF);
    } else {
        frame.push_back(127);
        for (int i = 7; i >= 0; i--) {
            frame.push_back((len >> (8 * i)) & 0xFF);
        }
    }

    frame.insert(frame.end(), message.begin(), message.end());
    return frame;
}


int set_nonblocking(int fd) {
    int flag = fcntl(fd, F_GETFL, 0);
    if (flag == -1) return -1;
    return fcntl(fd, F_SETFL, flag | O_NONBLOCK);
}

bool performHandshake(int client_fd) {
    char buffer[2048];
    ssize_t n = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
    if (n <= 0) return false;
    buffer[n] = '\0';

    std::string request(buffer);
    std::string websocketKeyHeader = "Sec-WebSocket-Key: ";
    size_t keyPos = request.find(websocketKeyHeader);
    if (keyPos == std::string::npos) return false;

    size_t keyStart = keyPos + websocketKeyHeader.length();
    size_t keyEnd = request.find("\r\n", keyStart);
    std::string clientKey = request.substr(keyStart, keyEnd - keyStart);

    std::string magicGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    std::string acceptKey = clientKey + magicGUID;

    // SHA1 Hash
    unsigned char sha1Hash[SHA_DIGEST_LENGTH];
    SHA1(reinterpret_cast<const unsigned char*>(acceptKey.c_str()), acceptKey.length(), sha1Hash);

    // Base64 encode
    std::string base64Key = base64Encode(sha1Hash, SHA_DIGEST_LENGTH);

    ostringstream response;
    response << "HTTP/1.1 101 Switching Protocols\r\n";
    response << "Upgrade: websocket\r\n";
    response << "Connection: Upgrade\r\n";
    response << "Sec-WebSocket-Accept: " << base64Key << "\r\n\r\n";

    send(client_fd, response.str().c_str(), response.str().length(), 0);
    std::cout << "Handshake completed with client " << client_fd << std::endl;
    return true;
}

void handleMessage(const int client_fd) {
    if (!handshakeDone[client_fd]) {
        if (performHandshake(client_fd)) handshakeDone[client_fd] = true;
        else {
            close(client_fd);
            cout << "Client " << client_fd << " disconnected" << endl;
        }
        return;
    }

    char buffer[2048];
    while (true) {
        ssize_t n = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break; // No more data
            close(client_fd);
            cout << "Client " << client_fd << " disconnected" << endl;
            return;
        } else if (n == 0) {
            close(client_fd);
            cout << "Client " << client_fd << " disconnected" << endl;
            return;
        }

        buffer[n] = '\0';
        string decodeData = decodeWebSocketFrame(buffer, n);
        cout << "Decoded " << decodeData << endl;
    }
}


void createServer(int port, const string& hostname) {
    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket < 0) {
        perror("socket");
        return;
    }

    sockaddr_in server{};
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    server.sin_addr.s_addr = inet_addr(hostname.c_str());

    if (server.sin_addr.s_addr == INADDR_NONE) {
        cerr << "Invalid IP address" << endl;
        return;
    }

    if (bind(serverSocket, reinterpret_cast<sockaddr*>(&server), sizeof(server)) < 0) {
        perror("bind");
        return;
    }

    if (listen(serverSocket, SOMAXCONN) < 0) {
        perror("listen");
        return;
    }

    cout << "WebSocket Server listening on port " << port << endl;

    int epoll_fd = epoll_create1(0);
    epoll_event event{};
    event.events = EPOLLIN;
    event.data.fd = serverSocket;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, serverSocket, &event);
    epoll_event client_events[3000];

    while (keep_running) {
        signal(SIGINT, inthandler); // Ctrl+C handler
        signal(SIGTERM, inthandler);
        int n = epoll_wait(epoll_fd, client_events, 3000, -1);
        for (int index = 0; index < n; index++) {
            cout << "Client " << client_events[index].data.fd << " event changed " << endl;
           if (client_events[index].data.fd == serverSocket) {
               int client_fd = accept(serverSocket, nullptr, nullptr);
               if (client_fd < 0) {
                   perror("accept");
                   continue;
               }
               set_nonblocking(client_fd);
               epoll_event client_event{};
               client_event.events = EPOLLIN | EPOLLET;
               client_event.data.fd = client_fd;
               epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &client_event);
               cout << "Client connected" << endl;
           }else {
               handleMessage(client_events[index].data.fd);
           }

        }
    }
    close(epoll_fd);
    close(serverSocket);
}
