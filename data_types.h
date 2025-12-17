#pragma once
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <arpa/inet.h>

template <typename T>
class Array {
public:
    void* arr;
    bool wasAlloc;
public:
    Array() {
        arr = nullptr;
        wasAlloc = false;
    }
    Array(void* start) {
        arr = start;
        *(uint32_t*)arr = ntohl(*(uint32_t*)arr);
        wasAlloc = false;
    }
    Array(const std::string& s) {
        arr = new uint8_t[4 + s.size()];
        *(uint32_t*)arr = s.size();
        memcpy((uint8_t*)arr + 4, s.c_str(), s.size());
        wasAlloc = true;
    }
    Array(const std::vector<T>& v) {
        arr = new uint8_t[4 + v.size() * sizeof(T)];
        *(uint32_t*)arr = v.size();
        memcpy((uint8_t*)arr + 4, v.data(), v.size() * sizeof(T));
        wasAlloc = true;
    }
    ~Array() {
        // if (wasAlloc) {
        //     delete[] (uint8_t*)arr;
        // }
    }
    uint32_t& size() {
        return *(uint32_t*)arr;
    }
    const uint32_t& size() const {
        return *(uint32_t*)arr;
    }
    uint32_t sizeInBytes() {
        return *(uint32_t*)arr * sizeof(T);
    }
    T& operator[](uint32_t i) {
        return ((T*)((uint32_t*)arr + 1))[i];
    }
    const T& operator[](uint32_t i) const {
        return ((T*)((uint32_t*)arr + 1))[i];
    }
    T* data() {
        return (T*)((uint8_t*)arr + 4);
    }
    const T* data() const {
        return (T*)((uint8_t*)arr + 4);
    }
    std::string toString() const {
        if (arr == nullptr) {
            return "";
        }
        uint32_t arraySize = *(const uint32_t*)arr;
        return std::string((const char*)data(), arraySize);
    }
};
