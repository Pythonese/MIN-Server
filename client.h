#include <cstdint>
#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <chrono>
#include <memory>
#include <openssl/sha.h>
#include "protocol.h"

namespace messenger {
    std::vector<uint8_t> ipv4_to_ipv6_mapped(const std::vector<uint8_t>& ipv4) {
        if (ipv4.size() != 4) {
            throw std::runtime_error("Invalid IPv4 address");
        }

        std::vector<uint8_t> ipv6(16, 0);
        // Set IPv4-mapped prefix: ::ffff:
        ipv6[10] = 0xFF;
        ipv6[11] = 0xFF;
        // Copy IPv4 address to last 4 bytes
        std::copy(ipv4.begin(), ipv4.end(), ipv6.begin() + 12);

        return ipv6;
    }

    // Check if 16-byte address is IPv4-mapped
    bool is_ipv4_mapped(const std::vector<uint8_t>& addr) {
        if (addr.size() != 16) return false;

        // Check for ::ffff: prefix
        for (int i = 0; i < 10; i++) {
            if (addr[i] != 0) return false;
        }
        return addr[10] == 0xFF && addr[11] == 0xFF;
    }

    // Extract IPv4 from IPv4-mapped address
    std::vector<uint8_t> extract_ipv4(const std::vector<uint8_t>& ipv6_mapped) {
        if (!is_ipv4_mapped(ipv6_mapped)) {
            throw std::runtime_error("Not an IPv4-mapped address");
        }

        return std::vector<uint8_t>(ipv6_mapped.begin() + 12, ipv6_mapped.end());
    }



    bool recv_all(int sockfd, void* buffer, size_t size) {
        char* ptr = static_cast<char*>(buffer);
        size_t total_received = 0;

        while (total_received < size) {
            ssize_t n = recv(sockfd, ptr + total_received, size - total_received, 0);

            if (n == 0) {
                // Connection closed by peer
                return false;
            }
            if (n < 0) {
                if (errno == EINTR) {
                    // Interrupted by signal, try again
                    continue;
                }
                // Other error
                return false;
            }

            total_received += n;
        }

        return true;
    }

    class Client {
    public:
        int socket_fd;
        std::vector<uint8_t> addr;
        int port;
        uint32_t id;
        std::string username = "NO USERNAME";
        uint8_t payloadBytes[IMAGE_RESOLUTION * 2]{};
        uint8_t payloadPtrsBytes[256]{};

    public:
        std::string getIPString() const {
            if (addr.size() == 4) {
                // IPv4
                char ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, addr.data(), ip_str, INET_ADDRSTRLEN);
                return std::string(ip_str);
            } else if (addr.size() == 16) {
                // IPv6
                char ip_str[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, addr.data(), ip_str, INET6_ADDRSTRLEN);
                return std::string(ip_str);
            }
            return "Unknown";
        }

        Client(int client_fd, const std::vector<uint8_t>& client_ip, uint16_t client_port) : socket_fd(client_fd), addr(client_ip), port(client_port) {
            if (socket_fd < 0) {
                throw std::runtime_error("Failed to create socket");
            }

            // Set socket timeout (10 seconds)
            struct timeval timeout;
            timeout.tv_sec = 10;
            timeout.tv_usec = 0;
            setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
            setsockopt(socket_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        }

        Client(const std::vector<uint8_t>& addr, int port) : addr(addr), port(port), socket_fd(-1) {
            // Create socket
            socket_fd = socket(AF_INET, SOCK_STREAM, 0);
            if (socket_fd < 0) {
                throw std::runtime_error("Failed to create socket");
            }

            // Set socket timeout (10 seconds)
            struct timeval timeout;
            timeout.tv_sec = 10;
            timeout.tv_usec = 0;
            setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
            setsockopt(socket_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        }

        ~Client() {
            close();
        }

        // void connect() {
        //     if (addr.size() != 4) {
        //         throw std::runtime_error("Invalid address format");
        //     }
        //
        //     struct sockaddr_in server_addr;
        //     std::memset(&server_addr, 0, sizeof(server_addr));
        //     server_addr.sin_family = AF_INET;
        //     server_addr.sin_port = htons(port);
        //     server_addr.sin_addr.s_addr = *reinterpret_cast<const uint32_t*>(addr.data());
        //
        //     if (::connect(socket_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        //         throw std::runtime_error("Connection failed");
        //     }
        // }

        void close() {
            if (socket_fd >= 0) {
                ::close(socket_fd);
                socket_fd = -1;
            }
        }

        // Utility functions
        std::vector<uint8_t> SHA256_hash(const std::vector<uint8_t>& data) {
            std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
            SHA256(data.data(), data.size(), hash.data());
            return hash;
        }

        uint32_t getCurrentTime() {
            auto now = std::chrono::system_clock::now();
            auto duration = now.time_since_epoch();
            return std::chrono::duration_cast<std::chrono::seconds>(duration).count();
        }

        Header makeHeader(HeaderType type, const Payload& payload) {
            try {
                // Convert payload to bytes for hashing
                // Note: You'll need to implement proper serialization for each payload type
                // This is a placeholder - you'll need to fill payloadBytes with actual payload data

                uint8_t hash[32];
                SHA256(payloadBytes, payload.size, hash);

                Header header;
                header.magic = htonl(PROTOCOL_MAGIC);
                header.type = htonl(static_cast<uint32_t>(type));
                header.size = htonl(payload.size);
                header.time = htonl(getCurrentTime());

                // Copy hash and signature (using hash as placeholder for signature)
                std::memcpy(header.hash, hash, 32);
                std::memcpy(header.signature, hash, 32);

                return header;
            } catch (const std::exception& e) {
                throw std::runtime_error(std::string("Failed to make header: ") + e.what());
            }
        }

        bool send_all(const void* buffer, size_t length) {
            if (!buffer && length > 0) {
                errno = EINVAL;
                return false;
            }

            if (socket_fd <= 0) {
                errno = EBADF;
                return false;
            }

            const char* ptr = static_cast<const char*>(buffer);
            size_t total_sent = 0;

            while (total_sent < length) {
                ssize_t sent = send(socket_fd, ptr + total_sent, length - total_sent, 0);
                if (sent < 0) {
                    if (errno == EINTR) continue; // Interrupted, try again

                    // Log specific error
                    std::cerr << "send() failed: " << strerror(errno)
                    << " (errno=" << errno << ")" << std::endl;
                    return false;
                }
                if (sent == 0) {
                    std::cerr << "Connection closed by peer" << std::endl;
                    return false;
                }
                total_sent += sent;
            }
            return true;
        }

        void sendHeader(const Header& header) {
            try {
                const uint8_t* headerBytes = reinterpret_cast<const uint8_t*>(&header);
                send_all(headerBytes, sizeof(Header));
                std::cout << "Header size: " <<header.size<<'\n';
            } catch (const std::exception& e) {
                throw std::runtime_error(std::string("Failed to send header: ") + e.what());
            }
        }

        void sendPayload(size_t size) {
            try {
                send_all(payloadBytes, size);
            } catch (const std::exception& e) {
                throw std::runtime_error(std::string("Failed to send payload: ") + e.what());
            }
        }

        // Client methods matching your Java API
        void sendKeyExchangeMessage() {
            KeyExchangePayload& payload = *new (payloadPtrsBytes) KeyExchangePayload({std::vector<uint8_t>(PUBLIC_KEY_LENGTH), std::vector<uint8_t>(PUBLIC_KEY_LENGTH)});
            payload.toBytes(payloadBytes);
            payload.hton();
            sendHeader(makeHeader(KEY_EXCHANGE, payload));
            sendPayload((payload.size));
        }

        void sendAuthMessage(const std::string& username, const std::string& password) {
            Array<uint8_t> userArray(username);
            Array<uint8_t> passArray(password);
            AuthPayload& payload = *new (payloadPtrsBytes) AuthPayload({username, password});
            payload.toBytes(payloadBytes);
            payload.hton();
            sendHeader(makeHeader(AUTH, payload));
            sendPayload(payload.size);
        }

        void sendCreateChatMessage(HeaderType type, const std::string& name, const std::vector<uint32_t>& messageIDs) {
            CreateChatPayload& payload = *new (payloadPtrsBytes) CreateChatPayload(name, messageIDs);
            payload.toBytes(payloadBytes);
            payload.hton();
            sendHeader(makeHeader(type, payload));
            sendPayload(payload.size);
        }

        void sendMessageCommandMessage(HeaderType type, const std::vector<uint32_t>& messageIDs) {
            MessageCommandPayload& payload = *new (payloadPtrsBytes) MessageCommandPayload(messageIDs);
            payload.toBytes(payloadBytes);
            payload.hton();
            sendHeader(makeHeader(type, payload));
            sendPayload(payload.size);
        }

        void sendSetUserChatSettingsMessage(const std::vector<uint32_t>& messageIDs, const std::vector<uint8_t>& settings) {
            SetUserChatSettingsPayload& payload = *new (payloadPtrsBytes) SetUserChatSettingsPayload(messageIDs, settings);
            payload.toBytes(payloadBytes);
            payload.hton();
            sendHeader(makeHeader(SET_USER_CHAT_SETTINGS, payload));
            sendPayload(payload.size);
        }

        void sendDirectChatMessage(HeaderType type, const std::string& username) {
            DirectChatPayload& payload = *new (payloadPtrsBytes) DirectChatPayload(username);
            payload.toBytes(payloadBytes);
            payload.hton();
            sendHeader(makeHeader(type, payload));
            sendPayload(payload.size);
        }

        void sendShareMessage(HeaderType type) {
            SharePayload& payload = *new (payloadPtrsBytes) SharePayload();
            payload.toBytes(payloadBytes);
            payload.hton();
            sendHeader(makeHeader(type, payload));
            sendPayload(payload.size);
        }

        void sendFileShareMessage(HeaderType type, const std::string& filename) {
            FileSharePayload& payload = *new (payloadPtrsBytes) FileSharePayload(filename);
            payload.toBytes(payloadBytes);
            payload.hton();
            sendHeader(makeHeader(type, payload));
            sendPayload(payload.size);
        }

        void sendProfileStringMessage(HeaderType type, const std::string& str) {
            ProfileStringPayload& payload = *new (payloadPtrsBytes) ProfileStringPayload(str);
            payload.toBytes(payloadBytes);
            payload.hton();
            sendHeader(makeHeader(type, payload));
            sendPayload(payload.size);
        }

        void sendAddProfileImageMessage(int width, int height, const std::vector<uint8_t>& image) {
            AddProfileImagePayload& payload = *new (payloadPtrsBytes) AddProfileImagePayload(width, height, image);
            payload.toBytes(payloadBytes);
            payload.hton();
            sendHeader(makeHeader(ADD_PROFILE_PICTURE, payload));
            sendPayload(payload.size);
        }

        void sendMoveProfileImageMessage(HeaderType type, int imageIndex, int offset) {
            MoveProfileImagePayload& payload = *new (payloadPtrsBytes) MoveProfileImagePayload(imageIndex, offset);
            payload.toBytes(payloadBytes);
            payload.hton();
            sendHeader(makeHeader(type, payload));
            sendPayload(payload.size);
        }

        void sendSendTextMessage(const std::vector<uint32_t>& messageIDs, const std::string& text) {
            SendTextPayload& payload = *new (payloadPtrsBytes) SendTextPayload(messageIDs, text);
            payload.toBytes(payloadBytes);
            payload.hton();
            sendHeader(makeHeader(TEXT, payload));
            // payload.text.size() = ntohl(payload.text.size());
            // payload.messageIDs.size() = ntohl(payload.messageIDs.size());
            sendPayload(payload.size);
            std::cout <<payload.size<<'\n';
            std::cout <<ntohl(payload.text.size())<<'\n';
            std::cout <<ntohl(payload.messageIDs.size())<<'\n';
        }

        void sendSendFileFrameMessage(const std::vector<uint32_t>& messageIDs, const std::string& filename, int index, const std::vector<uint8_t>& frame) {
            SendFileFramePayload& payload = *new (payloadPtrsBytes) SendFileFramePayload(messageIDs, filename, index, frame);
            payload.toBytes(payloadBytes);
            payload.hton();
            sendHeader(makeHeader(FILE_FRAME, payload));
            sendPayload(payload.size);
        }

        void sendDeleteMessageMessage(const std::vector<uint32_t>& messageIDs) {
            DeleteMessagePayload& payload = *new (payloadPtrsBytes) DeleteMessagePayload(messageIDs);
            payload.toBytes(payloadBytes);
            payload.hton();
            sendHeader(makeHeader(DELETE, payload));
            sendPayload(payload.size);
        }

        Header receiveHeader() {
            try {
                // Validate socket descriptor
                if (socket_fd <= 0) {
                    throw std::runtime_error("Invalid socket descriptor: " + std::to_string(socket_fd));
                }

                // Check if socket is still valid
                int error = 0;
                socklen_t len = sizeof(error);
                if (getsockopt(socket_fd, SOL_SOCKET, SO_ERROR, &error, &len) == 0) {
                    if (error != 0) {
                        throw std::runtime_error("Socket error: " + std::string(strerror(error)));
                    }
                } else {
                    // getsockopt failed - socket is likely closed
                    throw std::runtime_error("Socket is closed or invalid");
                }

                Header header;
                bool read = recv_all(socket_fd, &header, sizeof(Header));
                if (!read) {
                    throw std::runtime_error("not read");
                }

                // if (read == -1) {
                //     if (errno == EBADF) {
                //         throw std::runtime_error("Bad file descriptor - socket closed");
                //     } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                //         throw std::runtime_error("Receive timeout");
                //     } else if (errno == ECONNRESET) {
                //         throw std::runtime_error("Connection reset by peer");
                //     } else {
                //         throw std::runtime_error("Receive error: " + std::string(strerror(errno)));
                //     }
                // }
                //
                // if (read == 0) {
                //     throw std::runtime_error("Connection closed by peer");
                // }
                //
                // if (read != sizeof(Header)) {
                //     throw std::runtime_error("Header too short, received " +
                //     std::to_string(read) + " bytes, expected " +
                //     std::to_string(sizeof(Header)));
                // }
                header.magic = ntohl(header.magic);
                header.type = ntohl(header.type);
                header.size = ntohl(header.size);
                header.time = ntohl(header.time);
                if (header.magic != PROTOCOL_MAGIC) {
                    throw std::runtime_error("Invalid magic " + std::to_string(header.magic));
                }

                return header;
            } catch (const std::exception& e) {
                throw std::runtime_error(std::string("Failed to receive header: ") + e.what());
            }
        }

        Payload* receivePayload(const Header& header) {
            try {
                // std::vector<uint8_t> payloadBytes(header.size, 0);
                bool read = recv_all(socket_fd, payloadBytes, header.size);
                if (!read) {
                    throw std::runtime_error("not read");
                }
                // if (read == -1) {
                //     throw std::runtime_error("Connection closed or timeout");
                // }
                // if (read != header.size) {
                //     throw std::runtime_error("Payload too short");
                // }

                // Use your existing fromBytes function to parse the payload
                fromBytes(payloadBytes, static_cast<HeaderType>(header.type), payloadPtrsBytes);

                // Verify hash
                // std::vector<uint8_t> calculatedHash = SHA256_hash(payloadBytes);
                // if (std::memcmp(calculatedHash.data(), header.hash, 32) != 0) {
                //     delete payload;
                //     throw std::runtime_error("Invalid hash");
                // }

                return (Payload*)payloadPtrsBytes;
            } catch (const std::exception& e) {
                throw std::runtime_error(std::string("Failed to receive payload: ") + e.what());
            }
        }

        struct Message {
            Header header;
            Payload* payload;

            Message(const Header& header, Payload* payload)
            : header(header), payload(std::move(payload)) {}
        };

        Message receiveKeyExchangeMessage() {
            try {
                Header header = receiveHeader();
                Payload* payload = receivePayload(header);
                return Message(header, (payload));
            } catch (const std::exception& e) {
                throw std::runtime_error(std::string("Failed to receive key exchange message: ") + e.what());
            }
        }
    };

} // namespace messenger
