#pragma once

#include <stdexcept>
#include <vector>
#include <cstdint>
#include <Monocypher.hh>
#include <iostream>
#include <iomanip>


template<typename... Fs>
struct overload : Fs... { using Fs::operator()...; };


class KeysNotFound : public std::runtime_error {
    using std::runtime_error::runtime_error;

};
class CorruptedKeys : public std::runtime_error {
public:
    CorruptedKeys() : std::runtime_error("Encryption keys are corrupted. Manually erase the key file to reset. Note: you will lose the documents.") {}
    using std::runtime_error::runtime_error;
};


template<size_t size>
const monocypher::byte_array<size> zero{0};
template<size_t size>
const monocypher::byte_array<size> one{0xff};

// Concatenation of string and array.
template<size_t size>
std::vector<uint8_t> operator|(const std::string& a1, const monocypher::byte_array<size>& a2) {
    std::vector<uint8_t> result;

    result.reserve(a1.length() + size);
    result.insert(result.end(), a1.begin(), a1.end());
    result.insert(result.end(), a2.begin(), a2.end());

    return result;
}

// XOR between two arrays.
template<size_t size>
monocypher::secret_byte_array<size> operator^(const monocypher::secret_byte_array<size>& a1, const monocypher::secret_byte_array<size>& a2) {
    monocypher::secret_byte_array<size> result{a1};
    for (size_t i = 0; i < size; ++i) {
        result[i] ^= a2[i];
    }
    return result;
}

template<size_t size>
monocypher::byte_array<size> operator^(const monocypher::byte_array<size>& a1, const monocypher::byte_array<size>& a2) {
    monocypher::byte_array<size> result{a1};
    for (size_t i = 0; i < size; ++i) {
        result[i] ^= a2[i];
    }
    return result;
}

template<size_t size> requires (size % sizeof(size_t) == 0)
struct std::hash<monocypher::byte_array<size>> {
    std::size_t operator()(const monocypher::byte_array<size>& a) const noexcept {
        size_t h = 0;

        const size_t *arr = reinterpret_cast<const size_t*>(a.data());

        for (size_t i = 0; i < (size >> 3); ++i) {
            // NOTE: assuming uniformly distributed array.
            h ^= arr[i];
        }

        return h;
    }   
};


template<typename T>
constexpr monocypher::byte_array<sizeof(T)> serialize(const T& val) {
    return monocypher::byte_array<sizeof(T)>(reinterpret_cast<const void*>(&val), sizeof(T));
}


template<size_t size>
monocypher::byte_array<size>& operator--(monocypher::byte_array<size>& array) {
    // NOTE: little endian.
    size_t index = 0;
    while (index < size && array[index++]-- == 0);

    return array;
} 

template<size_t size>
void hexprint(const monocypher::byte_array<size>& array) {
    for (size_t i = size; i > 0; --i) {
        std::clog << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(array[i - 1]);
    }
    std::clog << std::endl;
}
