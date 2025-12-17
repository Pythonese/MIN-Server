#pragma once
#include <iostream>
#include <cstdint>
#include <cstring>
#include <new>
#include <stdexcept>
#include <arpa/inet.h>
#include "data_types.h" // Array<T>

namespace messenger {
    enum HeaderType : uint32_t {
        KEY_EXCHANGE,

        AUTH,

        // Commands
        // chat name, array of messageIDs
        CREATE_PERSISTENT_CHAT, CREATE_EPHEMERAL_CHAT,

        // message command(array of messageIDs)
        FREEZE_CHAT, UNFREEZE_CHAT,
        LOAD_SOME_MESSAGES, DOWNLOAD_FILE,
        GET_USER_CHAT_SETTINGS,

        // message command(array of messageIDs, chat settings)
        SET_USER_CHAT_SETTINGS,

        // direct chat
        START_DIRECT_CHAT, END_DIRECT_CHAT,

        // share()
        START_MICROPHONE_SHARE, END_MICROPHONE_SHARE,
        START_CAMERA_SHARE, END_CAMERA_SHARE,
        START_SCREEN_SHARE, END_SCREEN_SHARE,
        START_FILE_SHARE, END_FILE_SHARE,

        // share(filepath)
        ADD_FILE_TO_SHARE, REMOVE_FILE_FROM_SHARE,

        // profile string
        CHANGE_FIRST_NAME, CHANGE_USERNAME, CHANGE_PASSWORD,

        // profile image
        ADD_PROFILE_PICTURE,

        MOVE_PROFILE_PICTURE, REMOVE_PROFILE_PICTURE,

        TEXT, FILE_FRAME, DELETE
    };
    constexpr uint32_t PROTOCOL_MAGIC = 1;
    #pragma pack(push, 1)
    struct Header {
        uint32_t magic;
        uint32_t type;
        uint32_t size;
        uint32_t time;
        uint8_t hash[32];
        uint8_t signature[32];
    };
    #pragma pack(pop)
    void fromBytes(uint8_t* bytes, HeaderType type, uint8_t* payload);
    constexpr uint32_t PUBLIC_KEY_LENGTH = 32;
    constexpr uint32_t MESSAGE_IDS_LENGTH = 16;
    constexpr uint32_t TEXT_LENGTH = 1024;
    constexpr uint32_t CHAT_SETTINGS_LENGTH = 2048;
    constexpr uint32_t IMAGE_RESOLUTION = 7680 * 4320;
    constexpr uint32_t FILE_FRAME_LENGTH = 7680 * 4320;

    struct Payload {
        uint32_t size;
    };

    struct KeyExchangePayload : Payload {
        Array<uint8_t> publicKey;
        Array<uint8_t> verificationKey;

        KeyExchangePayload(Array<uint8_t> publicKey, Array<uint8_t> verificationKey) {
            this->publicKey = publicKey;
            this->verificationKey = verificationKey;
            size = 4 + publicKey.sizeInBytes() + 4 + verificationKey.sizeInBytes();
        }

        KeyExchangePayload(uint8_t* bytes) {
            this->publicKey = bytes;
            this->verificationKey = bytes + 4 + this->publicKey.sizeInBytes();
            if (this->publicKey.size() != PUBLIC_KEY_LENGTH) {
                throw std::invalid_argument(std::string("Invalid public key ") + std::to_string((this->publicKey.size())));
            }
            if (this->verificationKey.size() != PUBLIC_KEY_LENGTH) {
                throw std::invalid_argument("Invalid verifying key");
            }
            size = 4 + publicKey.sizeInBytes() + 4 + verificationKey.sizeInBytes();
        }

        void ntoh() {
            publicKey.size() = ntohl(publicKey.size());
            verificationKey.size() = ntohl(verificationKey.size());
        }

        void hton() {
            publicKey.size() = htonl(publicKey.size());
            verificationKey.size() = htonl(verificationKey.size());
        }

        void toBytes(uint8_t* bytes) {
            *(uint32_t*)bytes = publicKey.size();
            memcpy(bytes + 4, publicKey.data(), publicKey.sizeInBytes());
            *(uint32_t*)(bytes + 4 + publicKey.sizeInBytes()) = verificationKey.size();
            memcpy(bytes + 4 + publicKey.sizeInBytes() + 4, verificationKey.data(), verificationKey.sizeInBytes());

            publicKey.arr = bytes;
            verificationKey.arr = bytes + 4 + publicKey.sizeInBytes();
        }
    };

    struct AuthPayload : Payload {
        Array<uint8_t> username;
        Array<uint8_t> password;

        AuthPayload(Array<uint8_t> username, Array<uint8_t> password) {
            this->username = username;
            this->password = password;
            size = 4 + username.sizeInBytes() + 4 + password.sizeInBytes();
        }

        AuthPayload(uint8_t* bytes) {
            this->username = bytes;
            this->password = bytes + 4 + this->username.sizeInBytes();
            if (this->username.size() > PUBLIC_KEY_LENGTH) {
                throw std::invalid_argument("Username too long");
            }
            if (this->password.size() > PUBLIC_KEY_LENGTH) {
                throw std::invalid_argument("Password too long");
            }
            size = 4 + username.sizeInBytes() + 4 + password.sizeInBytes();
        }

        void ntoh() {
            username.size() = ntohl(username.size());
            password.size() = ntohl(password.size());
        }

        void hton() {
            username.size() = htonl(username.size());
            password.size() = htonl(password.size());
        }

        void toBytes(uint8_t* bytes) {
            *(uint32_t*)bytes = username.size();
            memcpy(bytes + 4, username.data(), username.sizeInBytes());
            *(uint32_t*)(bytes + 4 + username.sizeInBytes()) = password.size();
            memcpy(bytes + 4 + username.sizeInBytes() + 4, password.data(), password.sizeInBytes());
        }
    };

    struct CreateChatPayload : Payload {
        Array<uint8_t> name;
        Array<uint32_t> messageIDs;

        CreateChatPayload(Array<uint8_t> name, Array<uint32_t> messageIDs) {
            this->name = name;
            this->messageIDs = messageIDs;
            size = 4 + name.sizeInBytes() + 4 + messageIDs.sizeInBytes();
        }

        CreateChatPayload(uint8_t* bytes) {
            this->name = bytes;
            this->messageIDs = bytes + 4 + this->name.sizeInBytes();
            if (this->name.size() > PUBLIC_KEY_LENGTH) {
                throw std::invalid_argument("Name too long");
            }
            if (this->messageIDs.size() > MESSAGE_IDS_LENGTH) {
                throw std::invalid_argument("The chat is too deep");
            }
            size = 4 + name.sizeInBytes() + 4 + messageIDs.sizeInBytes();
        }

        void ntoh() {
            name.size() = ntohl(name.size());
            messageIDs.size() = ntohl(messageIDs.size());
            // Convert each uint32_t in messageIDs if needed
            for (size_t i = 0; i < messageIDs.size(); i++) {
                messageIDs[i] = ntohl(messageIDs[i]);
            }
        }

        void hton() {
            name.size() = htonl(name.size());
            // Convert each uint32_t in messageIDs if needed
            for (size_t i = 0; i < messageIDs.size(); i++) {
                messageIDs[i] = htonl(messageIDs[i]);
            }
            messageIDs.size() = htonl(messageIDs.size());
        }

        void toBytes(uint8_t* bytes) {
            *(uint32_t*)bytes = name.size();
            memcpy(bytes + 4, name.data(), name.sizeInBytes());
            *(uint32_t*)(bytes + 4 + name.sizeInBytes()) = messageIDs.size();
            memcpy(bytes + 4 + name.sizeInBytes() + 4, messageIDs.data(), messageIDs.sizeInBytes());
        }
    };

    struct MessageCommandPayload : Payload {
        Array<uint32_t> messageIDs;

        MessageCommandPayload(Array<uint32_t> messageIDs) {
            this->messageIDs = messageIDs;
            size = 4 + messageIDs.sizeInBytes();
        }

        MessageCommandPayload(uint8_t* bytes) {
            this->messageIDs = bytes;
            if (this->messageIDs.size() > MESSAGE_IDS_LENGTH) {
                throw std::invalid_argument("The chat is too deep");
            }
            size = 4 + messageIDs.sizeInBytes();
        }

        void ntoh() {
            messageIDs.size() = ntohl(messageIDs.size());
            // Convert each uint32_t in messageIDs if needed
            for (size_t i = 0; i < messageIDs.size(); i++) {
                messageIDs[i] = ntohl(messageIDs[i]);
            }
        }

        void hton() {
            // Convert each uint32_t in messageIDs if needed
            for (size_t i = 0; i < messageIDs.size(); i++) {
                messageIDs[i] = htonl(messageIDs[i]);
            }
            messageIDs.size() = htonl(messageIDs.size());
        }

        void toBytes(uint8_t* bytes) {
            *(uint32_t*)bytes = messageIDs.size();
            memcpy(bytes + 4, messageIDs.data(), messageIDs.sizeInBytes());
        }
    };

    struct SetUserChatSettingsPayload : Payload {
        Array<uint32_t> messageIDs;
        Array<uint8_t> settings;

        SetUserChatSettingsPayload(Array<uint32_t> messageIDs, Array<uint8_t> settings) {
            this->messageIDs = messageIDs;
            this->settings = settings;
            size = 4 + messageIDs.sizeInBytes() + 4 + settings.sizeInBytes();
        }

        SetUserChatSettingsPayload(uint8_t* bytes) {
            this->messageIDs = bytes;
            this->settings = bytes + 4 + this->messageIDs.sizeInBytes();
            if (this->messageIDs.size() > MESSAGE_IDS_LENGTH) {
                throw std::invalid_argument("The chat is too deep");
            }
            if (this->settings.size() > CHAT_SETTINGS_LENGTH) {
                throw std::invalid_argument("Settings too long");
            }
            size = 4 + messageIDs.sizeInBytes() + 4 + settings.sizeInBytes();
        }

        void ntoh() {
            messageIDs.size() = ntohl(messageIDs.size());
            settings.size() = ntohl(settings.size());
            // Convert each uint32_t in messageIDs if needed
            for (size_t i = 0; i < messageIDs.size(); i++) {
                messageIDs[i] = ntohl(messageIDs[i]);
            }
        }

        void hton() {
            // Convert each uint32_t in messageIDs if needed
            for (size_t i = 0; i < messageIDs.size(); i++) {
                messageIDs[i] = htonl(messageIDs[i]);
            }
            messageIDs.size() = htonl(messageIDs.size());
            settings.size() = htonl(settings.size());
        }

        void toBytes(uint8_t* bytes) {
            *(uint32_t*)bytes = messageIDs.size();
            memcpy(bytes + 4, messageIDs.data(), messageIDs.sizeInBytes());
            *(uint32_t*)(bytes + 4 + messageIDs.sizeInBytes()) = settings.size();
            memcpy(bytes + 4 + messageIDs.sizeInBytes() + 4, settings.data(), settings.sizeInBytes());
        }
    };

    struct DirectChatPayload : Payload {
        Array<uint8_t> username;

        DirectChatPayload(Array<uint8_t> username) {
            this->username = username;
            size = 4 + username.sizeInBytes();
        }

        DirectChatPayload(uint8_t* bytes) {
            this->username = bytes;
            if (this->username.size() > PUBLIC_KEY_LENGTH) {
                throw std::invalid_argument("Username too long");
            }
            size = 4 + username.sizeInBytes();
        }

        void ntoh() {
            username.size() = ntohl(username.size());
        }

        void hton() {
            username.size() = htonl(username.size());
        }

        void toBytes(uint8_t* bytes) {
            *(uint32_t*)bytes = username.size();
            memcpy(bytes + 4, username.data(), username.sizeInBytes());
        }
    };

    struct SharePayload : Payload {
        SharePayload() {
            size = 0;
        }

        SharePayload(uint8_t* bytes) {
            size = 0;
        }

        void ntoh() {
            // No fields to convert
        }

        void hton() {
            // No fields to convert
        }

        void toBytes(uint8_t* bytes) {
            // No data to write since size = 0
        }
    };

    struct FileSharePayload : Payload {
        Array<uint8_t> filename;

        FileSharePayload(Array<uint8_t> filename) {
            this->filename = filename;
            size = 4 + filename.sizeInBytes();
        }

        FileSharePayload(uint8_t* bytes) {
            this->filename = bytes;
            if (this->filename.size() > PUBLIC_KEY_LENGTH) {
                throw std::invalid_argument("Filename too long");
            }
            size = 4 + filename.sizeInBytes();
        }

        void ntoh() {
            filename.size() = ntohl(filename.size());
        }

        void hton() {
            filename.size() = htonl(filename.size());
        }

        void toBytes(uint8_t* bytes) {
            *(uint32_t*)bytes = filename.size();
            memcpy(bytes + 4, filename.data(), filename.sizeInBytes());
        }
    };

    struct ProfileStringPayload : Payload {
        Array<uint8_t> str;

        ProfileStringPayload(Array<uint8_t> str) {
            this->str = str;
            size = 4 + str.sizeInBytes();
        }

        ProfileStringPayload(uint8_t* bytes) {
            this->str = bytes;
            if (this->str.size() > PUBLIC_KEY_LENGTH) {
                throw std::invalid_argument("String too long");
            }
            size = 4 + str.sizeInBytes();
        }

        void ntoh() {
            str.size() = ntohl(str.size());
        }

        void hton() {
            str.size() = htonl(str.size());
        }

        void toBytes(uint8_t* bytes) {
            *(uint32_t*)bytes = str.size();
            memcpy(bytes + 4, str.data(), str.sizeInBytes());
        }
    };

    struct AddProfileImagePayload : Payload {
        uint32_t width;
        uint32_t height;
        Array<uint8_t> image;

        AddProfileImagePayload(uint32_t width, uint32_t height, Array<uint8_t> image) {
            this->width = width;
            this->height = height;
            this->image = image;
            size = 4 + 4 + 4 + image.sizeInBytes();
        }

        AddProfileImagePayload(uint8_t* bytes) {
            this->width = *reinterpret_cast<uint32_t*>(bytes);
            this->height = *reinterpret_cast<uint32_t*>(bytes + 4);
            this->image = bytes + 8;
            if ((this->image.size() / 4) > IMAGE_RESOLUTION) {
                throw std::invalid_argument("Image resolution too large");
            }
            size = 4 + 4 + 4 + image.sizeInBytes();
        }

        void ntoh() {
            width = ntohl(width);
            height = ntohl(height);
            image.size() = ntohl(image.size());
        }

        void hton() {
            width = htonl(width);
            height = htonl(height);
            image.size() = htonl(image.size());
        }

        void toBytes(uint8_t* bytes) {
            *(uint32_t*)bytes = width;
            *(uint32_t*)(bytes + 4) = height;
            *(uint32_t*)(bytes + 8) = image.size();
            memcpy(bytes + 12, image.data(), image.sizeInBytes());
        }
    };

    struct MoveProfileImagePayload : Payload {
        uint32_t imageIndex;
        uint32_t offset;

        MoveProfileImagePayload(uint32_t imageIndex, uint32_t offset) {
            this->imageIndex = imageIndex;
            this->offset = offset;
            size = 4 + 4;
        }

        MoveProfileImagePayload(uint8_t* bytes) {
            this->imageIndex = *reinterpret_cast<uint32_t*>(bytes);
            this->offset = *reinterpret_cast<uint32_t*>(bytes + 4);
            size = 4 + 4;
        }

        void ntoh() {
            imageIndex = ntohl(imageIndex);
            offset = ntohl(offset);
        }

        void hton() {
            imageIndex = htonl(imageIndex);
            offset = htonl(offset);
        }

        void toBytes(uint8_t* bytes) {
            *(uint32_t*)bytes = imageIndex;
            *(uint32_t*)(bytes + 4) = offset;
        }
    };

    struct SendTextPayload : Payload {
        Array<uint32_t> messageIDs;
        Array<uint8_t> text;

        SendTextPayload(Array<uint32_t> messageIDs, Array<uint8_t> text) {
            this->messageIDs = messageIDs;
            this->text = text;
            size = 4 + messageIDs.sizeInBytes() + 4 + text.sizeInBytes();
        }

        SendTextPayload(uint8_t* bytes) {
            this->messageIDs = bytes;
            this->text = bytes + 4 + this->messageIDs.sizeInBytes();
            if (this->messageIDs.size() > MESSAGE_IDS_LENGTH) {
                throw std::invalid_argument("The chat is too deep");
            }
            if (this->text.size() > TEXT_LENGTH) {
                throw std::invalid_argument("Text too long");
            }
            size = 4 + messageIDs.sizeInBytes() + 4 + text.sizeInBytes();
        }

        void ntoh() {
            messageIDs.size() = ntohl(messageIDs.size());
            text.size() = ntohl(text.size());
            // Convert each uint32_t in messageIDs if needed
            for (size_t i = 0; i < messageIDs.size(); i++) {
                messageIDs[i] = ntohl(messageIDs[i]);
            }
        }

        void hton() {
            // Convert each uint32_t in messageIDs if needed
            for (size_t i = 0; i < messageIDs.size(); i++) {
                messageIDs[i] = htonl(messageIDs[i]);
            }
            messageIDs.size() = htonl(messageIDs.size());
            text.size() = htonl(text.size());
        }

        void toBytes(uint8_t* bytes) {
            *(uint32_t*)bytes = messageIDs.size();
            memcpy(bytes + 4, messageIDs.data(), messageIDs.sizeInBytes());
            *(uint32_t*)(bytes + 4 + messageIDs.sizeInBytes()) = text.size();
            memcpy(bytes + 4 + messageIDs.sizeInBytes() + 4, text.data(), text.sizeInBytes());
            new (&messageIDs) Array<uint32_t>((void*)bytes);
            messageIDs.size() = htonl(messageIDs.size());
            new (&text) Array<uint8_t>((void*)(bytes + 4 + messageIDs.sizeInBytes()));
            text.size() = htonl(text.size());
            // messageIDs.size() = htonl(messageIDs.size());
            // std::cout << messageIDs.sizeInBytes()
        }
    };

    struct SendFileFramePayload : Payload {
        Array<uint32_t> messageIDs;
        Array<uint8_t> filename;
        uint32_t index;
        Array<uint8_t> frame;

        SendFileFramePayload(Array<uint32_t> messageIDs, Array<uint8_t> filename, uint32_t index, Array<uint8_t> frame) {
            this->messageIDs = messageIDs;
            this->filename = filename;
            this->index = index;
            this->frame = frame;
            size = 4 + messageIDs.sizeInBytes() + 4 + filename.sizeInBytes() + 4 + 4 + frame.sizeInBytes();
        }

        SendFileFramePayload(uint8_t* bytes) {
            this->messageIDs = bytes;
            this->filename = bytes + 4 + this->messageIDs.sizeInBytes();
            this->index = *reinterpret_cast<uint32_t*>(bytes + 4 + this->messageIDs.sizeInBytes() + 4 + this->filename.sizeInBytes());
            this->frame = bytes + 4 + this->messageIDs.sizeInBytes() + 4 + this->filename.sizeInBytes() + 4;

            if (this->messageIDs.size() > MESSAGE_IDS_LENGTH) {
                throw std::invalid_argument("The chat is too deep");
            }
            if (this->filename.size() > PUBLIC_KEY_LENGTH) {
                throw std::invalid_argument("Filename too long");
            }
            if (this->frame.size() > FILE_FRAME_LENGTH) {
                throw std::invalid_argument("File frame too long");
            }
            size = 4 + messageIDs.sizeInBytes() + 4 + filename.sizeInBytes() + 4 + 4 + frame.sizeInBytes();
        }

        void ntoh() {
            messageIDs.size() = ntohl(messageIDs.size());
            filename.size() = ntohl(filename.size());
            index = ntohl(index);
            frame.size() = ntohl(frame.size());
            // Convert each uint32_t in messageIDs if needed
            for (size_t i = 0; i < messageIDs.size(); i++) {
                messageIDs[i] = ntohl(messageIDs[i]);
            }
        }

        void hton() {
            // Convert each uint32_t in messageIDs if needed
            for (size_t i = 0; i < messageIDs.size(); i++) {
                messageIDs[i] = htonl(messageIDs[i]);
            }
            messageIDs.size() = htonl(messageIDs.size());
            filename.size() = htonl(filename.size());
            index = htonl(index);
            frame.size() = htonl(frame.size());
        }

        void toBytes(uint8_t* bytes) {
            *(uint32_t*)bytes = messageIDs.size();
            memcpy(bytes + 4, messageIDs.data(), messageIDs.sizeInBytes());
            *(uint32_t*)(bytes + 4 + messageIDs.sizeInBytes()) = filename.size();
            memcpy(bytes + 4 + messageIDs.sizeInBytes() + 4, filename.data(), filename.sizeInBytes());
            *(uint32_t*)(bytes + 4 + messageIDs.sizeInBytes() + 4 + filename.sizeInBytes()) = index;
            *(uint32_t*)(bytes + 4 + messageIDs.sizeInBytes() + 4 + filename.sizeInBytes() + 4) = frame.size();
            memcpy(bytes + 4 + messageIDs.sizeInBytes() + 4 + filename.sizeInBytes() + 8, frame.data(), frame.sizeInBytes());
        }
    };

    struct DeleteMessagePayload : Payload {
        Array<uint32_t> messageIDs;

        DeleteMessagePayload(Array<uint32_t> messageIDs) {
            this->messageIDs = messageIDs;
            size = 4 + messageIDs.sizeInBytes();
        }

        DeleteMessagePayload(uint8_t* bytes) {
            this->messageIDs = bytes;
            if (this->messageIDs.size() > MESSAGE_IDS_LENGTH) {
                throw std::invalid_argument("The chat is too deep");
            }
            size = 4 + messageIDs.sizeInBytes();
        }

        void ntoh() {
            messageIDs.size() = ntohl(messageIDs.size());
            // Convert each uint32_t in messageIDs if needed
            for (size_t i = 0; i < messageIDs.size(); i++) {
                messageIDs[i] = ntohl(messageIDs[i]);
            }
        }

        void hton() {
            // Convert each uint32_t in messageIDs if needed
            for (size_t i = 0; i < messageIDs.size(); i++) {
                messageIDs[i] = htonl(messageIDs[i]);
            }
            messageIDs.size() = htonl(messageIDs.size());
        }

        void toBytes(uint8_t* bytes) {
            *(uint32_t*)bytes = messageIDs.size();
            memcpy(bytes + 4, messageIDs.data(), messageIDs.sizeInBytes());
        }
    };
}
