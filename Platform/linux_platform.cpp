//
// Created by karthi on 15/07/25.
//
#include "platform.h"
#include <cstring>
#include <iostream>
#include <unordered_set>
#include <vector>
#include <string>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/sha.h>

using namespace std;

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

    unordered_set<int> websocketClients;
    fd_set masterSet, readSet;
    FD_ZERO(&masterSet);
    FD_SET(serverSocket, &masterSet);
    int maxFd = serverSocket;

    while (true) {
        readSet = masterSet;

        if (select(maxFd + 1, &readSet, nullptr, nullptr, nullptr) < 0) {
            perror("select");
            break;
        }

        for (int fd = 0; fd <= maxFd; fd++) {
            if (!FD_ISSET(fd, &readSet)) continue;

            if (fd == serverSocket) {
                // Accept new connection
                sockaddr_in client{};
                socklen_t clientLen = sizeof(client);
                int clientSocket = accept(serverSocket, reinterpret_cast<sockaddr*>(&client), &clientLen);
                if (clientSocket < 0) {
                    perror("accept");
                    continue;
                }

                FD_SET(clientSocket, &masterSet);
                if (clientSocket > maxFd) maxFd = clientSocket;

                char ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &client.sin_addr, ip, INET_ADDRSTRLEN);
                cout << "New connection from " << ip << ":" << ntohs(client.sin_port) << endl;

            } else {
                // Existing client sent data
                char buffer[2048];
                int bytesRead = recv(fd, buffer, sizeof(buffer), 0);
                if (bytesRead <= 0) {
                    if (bytesRead == 0)
                        cout << "Client disconnected (fd: " << fd << ")" << endl;
                    else
                        perror("recv");

                    close(fd);
                    FD_CLR(fd, &masterSet);
                    websocketClients.erase(fd);
                    continue;
                }

                buffer[bytesRead] = '\0';

                if (websocketClients.find(fd) == websocketClients.end()) {
                    // Handle WebSocket handshake
                    string request(buffer);
                    size_t keyPos = request.find("Sec-WebSocket-Key: ");
                    if (keyPos != string::npos) {
                        keyPos += 19;
                        size_t end = request.find("\r\n", keyPos);
                        string clientKey = request.substr(keyPos, end - keyPos);
                        string acceptKey = generateAcceptKey(clientKey);

                        string response =
                            "HTTP/1.1 101 Switching Protocols\r\n"
                            "Upgrade: websocket\r\n"
                            "Connection: Upgrade\r\n"
                            "Sec-WebSocket-Accept: " + acceptKey + "\r\n\r\n";

                        send(fd, response.c_str(), response.size(), 0);
                        websocketClients.insert(fd);
                        cout << "Handshake complete for fd " << fd << endl;
                    } else {
                        cerr << "Invalid handshake from fd " << fd << endl;
                        close(fd);
                        FD_CLR(fd, &masterSet);
                    }

                } else {
                    // Decode WebSocket message and echo
                    string decoded = decodeWebSocketFrame(buffer, bytesRead);
                    cout << "Message from fd " << fd << ": " << decoded << endl;

                    vector<char> reply = encodeWebSocketFrame("Echo: " + decoded);
                    send(fd, reply.data(), reply.size(), 0);
                }
            }
        }
    }

    close(serverSocket);
}
