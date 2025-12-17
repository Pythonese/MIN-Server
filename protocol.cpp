#include "protocol.h"

void messenger::fromBytes(uint8_t* bytes, HeaderType type, uint8_t* payload) {
    if (type == KEY_EXCHANGE) {
        new (payload) KeyExchangePayload(bytes);
        ((KeyExchangePayload*)payload)->ntoh();
    }
    else if (type == AUTH) {
        new (payload) AuthPayload(bytes);
        ((AuthPayload*)payload)->ntoh();
    }
    else if (type >= CREATE_PERSISTENT_CHAT && type <= CREATE_EPHEMERAL_CHAT) {
        new (payload) CreateChatPayload(bytes);
        ((CreateChatPayload*)payload)->ntoh();
    }
    else if (type >= FREEZE_CHAT && type <= GET_USER_CHAT_SETTINGS) {
        new (payload) MessageCommandPayload(bytes);
        std::cout << ((MessageCommandPayload*)payload)->messageIDs.size() << '\n';
        ((MessageCommandPayload*)payload)->messageIDs.size() = htonl(((MessageCommandPayload*)payload)->messageIDs.size());
        ((MessageCommandPayload*)payload)->ntoh();
    }
    else if (type == SET_USER_CHAT_SETTINGS) {
        new (payload) SetUserChatSettingsPayload(bytes);
        ((SetUserChatSettingsPayload*)payload)->ntoh();
    }
    else if (type >= START_DIRECT_CHAT && type <= END_DIRECT_CHAT) {
        new (payload) DirectChatPayload(bytes);
        ((DirectChatPayload*)payload)->ntoh();
    }
    else if (type >= START_MICROPHONE_SHARE && type <= END_FILE_SHARE) {
        new (payload) SharePayload(bytes);
        ((SharePayload*)payload)->ntoh();
    }
    else if (type >= ADD_FILE_TO_SHARE && type <= REMOVE_FILE_FROM_SHARE) {
        new (payload) FileSharePayload(bytes);
        ((FileSharePayload*)payload)->ntoh();
    }
    else if (type >= CHANGE_FIRST_NAME && type <= CHANGE_PASSWORD) {
        new (payload) ProfileStringPayload(bytes);
        ((ProfileStringPayload*)payload)->ntoh();
    }
    else if (type == ADD_PROFILE_PICTURE) {
        new (payload) AddProfileImagePayload(bytes);
        ((AddProfileImagePayload*)payload)->ntoh();
    }
    else if (type >= MOVE_PROFILE_PICTURE && type <= REMOVE_PROFILE_PICTURE) {
        new (payload) MoveProfileImagePayload(bytes);
        ((MoveProfileImagePayload*)payload)->ntoh();
    }
    else if (type == TEXT) {
        new (payload) SendTextPayload(bytes);
        std::cout << ((SendTextPayload*)payload)->text.size() << '\n';
        std::cout << ((SendTextPayload*)payload)->messageIDs.size() << '\n';
        ((SendTextPayload*)payload)->text.size() = htonl(((SendTextPayload*)payload)->text.size());
        ((SendTextPayload*)payload)->messageIDs.size() = htonl(((SendTextPayload*)payload)->messageIDs.size());
        ((SendTextPayload*)payload)->ntoh();
    }
    else if (type == FILE_FRAME) {
        new (payload) SendFileFramePayload(bytes);
        ((SendFileFramePayload*)payload)->ntoh();
    }
    else if (type == DELETE) {
        new (payload) DeleteMessagePayload(bytes);
        ((DeleteMessagePayload*)payload)->ntoh();
    }
    else {
        throw std::invalid_argument("Invalid type");
    }
}
