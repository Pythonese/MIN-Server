#pragma once

#include <cstdint>
#include <pqxx/pqxx>
#include <openssl/sha.h>
#include <vector>
#include <string>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <iostream>
#include <cstring>
#include <tuple>

class DatabaseManager {
private:
    pqxx::connection conn;

public:
    DatabaseManager(const std::string& conn_string) : conn(conn_string) {
        if (!conn.is_open()) {
            throw std::runtime_error("Failed to connect to database");
        }
    }

    ~DatabaseManager() {
        conn.close();
    }

    // SHA256 hash function
    std::vector<uint8_t> SHA256_hash(const std::vector<uint8_t>& data) {
        std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
        SHA256(data.data(), data.size(), hash.data());
        return hash;
    }

    // Convert string to vector
    std::vector<uint8_t> string_to_vector(const std::string& str) {
        return std::vector<uint8_t>(str.begin(), str.end());
    }

    // Convert hash to hex string
    std::string hash_to_hex(const std::vector<uint8_t>& hash) {
        std::stringstream ss;
        for (uint8_t byte : hash) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        }
        return ss.str();
    }

    // Main authentication function
    bool auth(const std::string& username, const std::string& password) {
        if (has_account(username)) {
            if (password_correct(username, password)) {
                std::cout << "Authentication successful for user: " << username << std::endl;
                return true;
            } else {
                std::cout << "Incorrect password for user: " << username << std::endl;
                return false;
            }
        } else {
            sign_up(username, password);
        }
        return true;
    }

    // Check if account exists
    bool has_account(const std::string& username) {
        try {
            pqxx::work txn(conn);
            std::string query = "SELECT EXISTS(SELECT 1 FROM users WHERE username = $1)";
            pqxx::result result = txn.exec_params(query, username);
            txn.commit();

            if (!result.empty()) {
                return result[0][0].as<bool>();
            }
            return false;
        } catch (const std::exception& e) {
            std::cerr << "Error checking account existence: " << e.what() << std::endl;
            return false;
        }
    }

    // Verify password correctness
    bool password_correct(const std::string& username, const std::string& password) {
        try {
            // Calculate hash of provided password
            auto password_hash = SHA256_hash(string_to_vector(password));
            std::string provided_hash_hex = hash_to_hex(password_hash);

            pqxx::work txn(conn);
            std::string query = "SELECT password_hash FROM users WHERE username = $1";
            pqxx::result result = txn.exec_params(query, username);
            txn.commit();

            if (!result.empty()) {
                std::string stored_hash = result[0][0].as<std::string>();
                return provided_hash_hex == stored_hash;
            }
            return false;
        } catch (const std::exception& e) {
            std::cerr << "Error verifying password: " << e.what() << std::endl;
            return false;
        }
    }

    // Create new account
    void sign_up(const std::string& username, const std::string& password) {
        try {
            // ENFORCE 32-CHAR LIMIT
            std::string short_username = username.substr(0, 32);
            std::string firstname = short_username.substr(0, 32); // Same as username

            auto password_hash = SHA256_hash(string_to_vector(password));
            std::string password_hash_hex = hash_to_hex(password_hash);

            pqxx::work txn(conn);
            std::string query = "INSERT INTO users (username, firstname, password_hash) "
            "VALUES ($1, $2, $3) RETURNING id";
            pqxx::result result = txn.exec_params(query,
                                                  short_username, firstname, password_hash_hex);
            txn.commit();

            if (!result.empty()) {
                int32_t user_id = result[0][0].as<int32_t>();
                std::cout << "Account created for: " << short_username
                << " (truncated from: " << username << ")" << std::endl;
            }
        } catch (const std::exception& e) {
            std::cerr << "Error during sign up: " << e.what() << std::endl;
            throw;
        }
    }

    // Save a message
    void save_message(uint32_t chat_id, uint32_t user_id,
                      const std::chrono::system_clock::time_point& timestamp,
                      uint32_t content_size, const uint8_t* content) {
        try {
            // Convert timestamp to PostgreSQL format
            auto time_t = std::chrono::system_clock::to_time_t(timestamp);
            std::tm tm = *std::gmtime(&time_t);
            std::stringstream ss;
            ss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
            std::string timestamp_str = ss.str();

            // Convert content to string
            std::string content_str;
            if (content && content_size > 0) {
                content_str.assign(reinterpret_cast<const char*>(content),
                                   std::min(content_size, static_cast<uint32_t>(1024)));
            }

            pqxx::work txn(conn);
            std::string query = "INSERT INTO messages (user_id, parent_id, created_at, content) "
            "VALUES ($1, $2, $3::timestamp, $4) "
            "RETURNING id";

                pqxx::result result = txn.exec_params(query,
                                                      user_id,
                                                      chat_id,
                                                      timestamp_str,
                                                      content_str);
                txn.commit();

                if (!result.empty()) {
                    int32_t message_id = result[0][0].as<int32_t>();
                    std::cout << "Message saved with ID: " << message_id << std::endl;
                }
        } catch (const std::exception& e) {
            std::cerr << "Error saving message: " << e.what() << std::endl;
            throw;
        }
                      }

                      // Get last message in a chat
                      std::tuple<uint32_t, uint32_t> get_last_message(uint32_t chat_id, uint8_t* content_buffer, uint32_t buffer_size) {
                          try {
                              pqxx::work txn(conn);
                              std::string query = "SELECT id, content, user_id FROM messages "
                              "WHERE parent_id = $1 AND is_deleted = false AND is_hidden = false "
                              "ORDER BY created_at DESC LIMIT 1";

                              pqxx::result result = txn.exec_params(query, chat_id);
                              txn.commit();

                              if (!result.empty()) {
                                  uint32_t message_id = result[0][0].as<uint32_t>();
                                  std::string content = result[0][1].as<std::string>();
                                  uint32_t user_id = result[0][2].as<uint32_t>();

                                  // Copy content to buffer if provided
                                  if (content_buffer && buffer_size > 0) {
                                      size_t copy_size = std::min(content.size(), static_cast<size_t>(buffer_size - 1));
                                      if (copy_size > 0) {
                                          std::memcpy(content_buffer, content.c_str(), copy_size);
                                      }
                                      content_buffer[copy_size] = '\0';
                                  }

                                  return std::tuple<uint32_t, uint32_t>(message_id, user_id);
                              }
                              return std::tuple<uint32_t, uint32_t>(0, 0);
                          } catch (const std::exception& e) {
                              std::cerr << "Error getting last message: " << e.what() << std::endl;
                              return std::tuple<uint32_t, uint32_t>(0, 0);
                          }
                      }

                      // Get message with ID less than specified in a chat
                      std::tuple<uint32_t, uint32_t> get_last_message(uint32_t message_id, uint32_t chat_id,
                                                uint8_t* content_buffer, uint32_t buffer_size) {
                          try {
                              pqxx::work txn(conn);
                              std::string query = "SELECT id, content, user_id FROM messages "
                              "WHERE parent_id = $1 AND id < $2 "
                              "AND is_deleted = false AND is_hidden = false "
                              "ORDER BY created_at DESC LIMIT 1";

                              pqxx::result result = txn.exec_params(query, chat_id, message_id);
                              txn.commit();

                              if (!result.empty()) {
                                  uint32_t new_message_id = result[0][0].as<uint32_t>();
                                  std::string content = result[0][1].as<std::string>();
                                  uint32_t user_id = result[0][2].as<uint32_t>();

                                  // Copy content to buffer if provided
                                  if (content_buffer && buffer_size > 0) {
                                      size_t copy_size = std::min(content.size(), static_cast<size_t>(buffer_size - 1));
                                      if (copy_size > 0) {
                                          std::memcpy(content_buffer, content.c_str(), copy_size);
                                      }
                                      content_buffer[copy_size] = '\0';
                                  }

                                  return std::tuple<uint32_t, uint32_t>(new_message_id, user_id);
                              }
                              return std::tuple<uint32_t, uint32_t>(0, 0);
                          } catch (const std::exception& e) {
                              std::cerr << "Error getting previous message: " << e.what() << std::endl;
                              return std::tuple<uint32_t, uint32_t>(0, 0);
                          }
                                                }

                                                // Get first name of a user
                                                std::string get_first_name(uint32_t user_id) {
                                                    try {
                                                        pqxx::work txn(conn);
                                                        std::string query = "SELECT firstname FROM users WHERE id = $1";
                                                        pqxx::result result = txn.exec_params(query, user_id);
                                                        txn.commit();

                                                        if (!result.empty()) {
                                                            return result[0][0].as<std::string>();
                                                        }
                                                        return "";
                                                    } catch (const std::exception& e) {
                                                        std::cerr << "Error getting first name: " << e.what() << std::endl;
                                                        return "";
                                                    }
                                                }

                                                // Get user ID from username
                                                uint32_t get_user_id(const std::string& username) {
                                                    try {
                                                        pqxx::work txn(conn);
                                                        std::string query = "SELECT id FROM users WHERE username = $1";
                                                        pqxx::result result = txn.exec_params(query, username);
                                                        txn.commit();

                                                        if (!result.empty()) {
                                                            return result[0][0].as<uint32_t>();
                                                        }
                                                        return 0;
                                                    } catch (const std::exception& e) {
                                                        std::cerr << "Error getting user ID: " << e.what() << std::endl;
                                                        return 0;
                                                    }
                                                }
};
