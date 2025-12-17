#include <cstdint>
#include <memory>
#include <unordered_map>
#include <functional>
#include <thread>
#include <mutex>
#include "client.h"
#include "db.h"
#include "protocol.h"

namespace messenger {

    class Server {
    private:
        DatabaseManager db = DatabaseManager(
            "host=localhost "
            "port=5432 "
            "dbname=app_database "
            "user=user1 "
            "password=password1"
        );
        int server_fd;
        bool running;
        std::unordered_map<int, std::shared_ptr<Client>> clients;
        std::unordered_map<int, std::string> usernames;
        std::mutex map_mutex;
        int next_client_id;

    public:
        Server() : server_fd(-1), running(false), next_client_id(1) {}

        ~Server() {
            stop();
        }

        // Start server on specified port with IPv6 dual-stack support
        void start(uint16_t port, bool ipv6_only = false) {
            // Create IPv6 socket
            server_fd = socket(AF_INET6, SOCK_STREAM, 0);
            if (server_fd < 0) {
                throw std::runtime_error("Failed to create socket: " + std::string(strerror(errno)));
            }

            // Configure socket
            configure_socket(server_fd, ipv6_only);

            // Bind to all interfaces
            sockaddr_in6 addr{};
            addr.sin6_family = AF_INET6;
            addr.sin6_addr = in6addr_any;  // :: (all IPv6 interfaces)
            addr.sin6_port = htons(port);

            if (bind(server_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
                close(server_fd);
                throw std::runtime_error("Bind failed: " + std::string(strerror(errno)));
            }

            // Start listening
            if (listen(server_fd, SOMAXCONN) < 0) {
                close(server_fd);
                throw std::runtime_error("Listen failed: " + std::string(strerror(errno)));
            }

            std::cout << "Server started on port " << port
            << " (IPv6 dual-stack)" << std::endl;

            running = true;
            accept_connections();
        }

        void stop() {
            running = false;
            if (server_fd >= 0) {
                close(server_fd);
                server_fd = -1;
            }

            // Close all client connections
            for (auto& [fd, client] : clients) {
                client->close();
            }
            clients.clear();
        }

    private:
        void configure_socket(int fd, bool ipv6_only) {
            // Enable dual-stack by default (allow IPv4 connections on IPv6 socket)
            int opt = ipv6_only ? 1 : 0;
            if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt)) < 0) {
                close(fd);
                throw std::runtime_error("setsockopt failed: " + std::string(strerror(errno)));
            }

            // Enable address reuse
            opt = 1;
            if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
                close(fd);
                throw std::runtime_error("setsockopt SO_REUSEADDR failed: " + std::string(strerror(errno)));
            }

            #ifdef SO_REUSEPORT
            if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0) {
                // Not critical, just log
                std::cerr << "Warning: SO_REUSEPORT not supported" << std::endl;
            }
            #endif
        }

        void accept_connections() {
            while (running) {
                sockaddr_storage client_addr{};
                socklen_t addr_len = sizeof(client_addr);

                int client_fd = accept(server_fd,
                                       reinterpret_cast<sockaddr*>(&client_addr),
                                       &addr_len);

                if (client_fd < 0) {
                    if (errno == EINTR) continue;  // Interrupted by signal
                    perror("accept failed");
                    continue;
                }

                // Handle new client
                handle_new_client(client_fd, client_addr);
            }
        }

        void handle_new_client(int client_fd, const sockaddr_storage& client_addr) {
            try {
                // Extract client IP and port
                std::vector<uint8_t> client_ip;
                uint16_t client_port = 0;

                if (client_addr.ss_family == AF_INET) {
                    // IPv4 connection
                    auto* sa = reinterpret_cast<const sockaddr_in*>(&client_addr);
                    client_port = ntohs(sa->sin_port);
                    const uint8_t* ip_bytes = reinterpret_cast<const uint8_t*>(&sa->sin_addr);
                    client_ip.assign(ip_bytes, ip_bytes + 4);

                    std::cout << "New IPv4 client: "
                    << format_ipv4(sa->sin_addr)
                    << ":" << client_port << std::endl;

                } else if (client_addr.ss_family == AF_INET6) {
                    // IPv6 connection
                    auto* sa = reinterpret_cast<const sockaddr_in6*>(&client_addr);
                    client_port = ntohs(sa->sin6_port);
                    const uint8_t* ip_bytes = sa->sin6_addr.s6_addr;
                    client_ip.assign(ip_bytes, ip_bytes + 16);

                    std::cout << "New IPv6 client: ["
                    << format_ipv6(sa->sin6_addr)
                    << "]:" << client_port << std::endl;

                } else {
                    close(client_fd);
                    return;
                }

                // Create Client object
                auto client = std::make_shared<Client>(client_fd, client_ip, client_port);

                // Store in client map
                clients[client_fd] = client;

                // Start client handler thread
                std::thread(&Server::client_handler, this, client_fd).detach();

            } catch (const std::exception& e) {
                std::cerr << "Failed to handle new client: " << e.what() << std::endl;
                close(client_fd);
            }
        }

        void client_handler(int client_fd) {
            auto it = clients.find(client_fd);
            if (it == clients.end()) {
                return;
            }

            auto client = it->second;

            try {
                // Main client handling loop
                while (running) {
                    // Receive and process messages
                    Header header = client->receiveHeader();

                    // Dispatch based on message type
                    handle_client_message(client, header);
                }
            } catch (const std::exception& e) {
                std::cerr << "Client " << client->getIPString()
                << " error: " << e.what() << std::endl;
            }

            // Cleanup
            client->close();
            clients.erase(client_fd);
        }

        void handle_client_message(std::shared_ptr<Client> client, const Header& header) {
            try {
                // Receive payload based on header
                std::cout << "start handle\n";

                Payload& payload = *client->receivePayload(header);
                std::cout << "Recieved payload\n";

                // Process based on message type
                switch (static_cast<HeaderType>(header.type)) {
                    case KEY_EXCHANGE:
                        handle_key_exchange(client, payload);
                        break;
                    case AUTH:
                        handle_auth(client, payload);
                        break;
                    case TEXT:
                        std::cout << "start handle text message\n";
                        handle_text_message(client, payload);
                        break;
                    case LOAD_SOME_MESSAGES:
                        handle_load_some_messages_message(client, payload);
                        break;
                    default:
                        std::cerr << "Unknown message type: " << header.type << std::endl;
                        break;
                }

            } catch (const std::exception& e) {
                std::cerr << "Failed to handle message from client "
                << client->getIPString() << ": " << e.what() << std::endl;
            }
        }

        // Message handlers
        void handle_key_exchange(std::shared_ptr<Client> client, const Payload& payload) {
            // Process key exchange
            std::cout << "Key exchange from client: " << client->getIPString() << std::endl;

            // Send response
            client->sendKeyExchangeMessage();
            std::cout << "Key exchange to client: " << client->getIPString() << std::endl;

        }

        void handle_auth(std::shared_ptr<Client> client, Payload& payload) {
            // Process authentication
            // ... auth logic ...
            AuthPayload& authPayload = *(AuthPayload*)&payload;
            authPayload.ntoh();
            std::cout << "Client username: " << authPayload.username.toString() << '\n';
            std::cout << "Client password: " << authPayload.password.toString() << '\n';
            std::cout << authPayload.username.size() << '\n';
            bool authOK = db.auth(authPayload.username.toString(), authPayload.password.toString());
            std::cout << "auth checked\n";
            if (authOK) {
                client->id = db.get_user_id(authPayload.username.toString());
                // uint32_t last_message_id = db.get_last_message(1, nullptr, 0);
                client->sendSendTextMessage({0}, "OK");
                // std::lock_guard<std::mutex> lock(map_mutex);
                // usernames[client->socket_fd] = authPayload.username.toString();
                // client->username = authPayload.username.toString();
                std::cout << "Auth from client: " << client->getIPString() << std::endl;
            } else {
                client->sendSendTextMessage({0}, "WRONG");
            }
        }

        void handle_text_message(std::shared_ptr<Client> client, Payload& payload) {
            if (client->username == "") {
                std::cout << "Client not auth\n";
                return;
            }
            // Process text message
            // ... text handling logic ...
            std::cout << "start handle text message\n";
            SendTextPayload& sendTextPayload = *(SendTextPayload*)&payload;
            std::cout << sendTextPayload.text.size() << '\n';
            // sendTextPayload.ntoh();
            // sendTextPayload.text.size() = ntohl(sendTextPayload.text.size());
            // sendTextPayload.messageIDs.size() = ntohl(sendTextPayload.messageIDs.size());
            db.save_message(1, client->id, std::chrono::system_clock::now(), sendTextPayload.text.size(), (uint8_t*)sendTextPayload.text.arr + 4);
            uint8_t content_buffer[1024]{};
            auto ids = db.get_last_message(1, content_buffer, 1024);
            uint32_t message_id = std::get<0>(ids);
            uint32_t user_id = std::get<1>(ids);
            // std::lock_guard<std::mutex> lock(map_mutex);
            std::cout << "Text message to client: " << db.get_first_name(user_id) + " " + std::string((const char*)content_buffer) << std::endl;
            client->sendSendTextMessage({1, message_id}, db.get_first_name(user_id) + " " + std::string((const char*)content_buffer));
            std::cout << "Text message from client: " << client->getIPString() << std::endl;
        }

        void handle_load_some_messages_message(std::shared_ptr<Client> client, const Payload& payload) {
            const MessageCommandPayload& messageCommandPayload = *(MessageCommandPayload*)&payload;
            uint8_t content_buffer[1024]{};
            if (messageCommandPayload.messageIDs.size() == 1) {
                auto ids = db.get_last_message(1, content_buffer, 1024);
                uint32_t message_id = std::get<0>(ids);
                uint32_t user_id = std::get<1>(ids);
                client->sendSendTextMessage({1, message_id}, db.get_first_name(user_id) + " " + std::string((const char*)content_buffer));
            } else {
                auto ids = db.get_last_message(messageCommandPayload.messageIDs[messageCommandPayload.messageIDs.size() - 1], 1, content_buffer, 1024);
                uint32_t message_id = std::get<0>(ids);
                uint32_t user_id = std::get<1>(ids);
                client->sendSendTextMessage({1, message_id}, db.get_first_name(user_id) + " " + std::string((const char*)content_buffer));
            }
            std::cout << "Text message from server: " << client->getIPString() << std::endl;
        }

        // Helper functions
        static std::string format_ipv4(const in_addr& addr) {
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));
            return std::string(ip_str);
        }

        static std::string format_ipv6(const in6_addr& addr) {
            char ip_str[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &addr, ip_str, sizeof(ip_str));
            return std::string(ip_str);
        }

        // Check if IPv6 address is IPv4-mapped
        static bool is_ipv4_mapped(const in6_addr& addr6) {
            const uint8_t* bytes = addr6.s6_addr;
            return (bytes[0] == 0 && bytes[1] == 0 && bytes[2] == 0 && bytes[3] == 0 &&
            bytes[4] == 0 && bytes[5] == 0 && bytes[6] == 0 && bytes[7] == 0 &&
            bytes[8] == 0 && bytes[9] == 0 && bytes[10] == 0xFF && bytes[11] == 0xFF);
        }

        // Extract IPv4 from IPv4-mapped IPv6 address
        static in_addr extract_ipv4(const in6_addr& addr6) {
            in_addr addr4;
            memcpy(&addr4, &addr6.s6_addr[12], 4);
            return addr4;
        }
    };

} // namespace messenger

int main() {
    try {
        // Create and start server on port 8080
        messenger::Server server;
        server.start(8080);  // Dual-stack: accepts both IPv4 and IPv6

        // Server will run until interrupted
        std::cout << "Press Ctrl+C to stop server..." << std::endl;

        // Keep main thread alive
        while (true) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }

    } catch (const std::exception& e) {
        std::cerr << "Server error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
