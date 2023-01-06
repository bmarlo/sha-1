#include "marlo/sha1.hpp"
#include <array>

namespace marlo {

sha1::sha1() : _state{0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0}, _msglen(0)
{
    _hash.reserve(sha1::hash_size + sha1::block_size);
    _hash.resize(sha1::hash_size);
}

sha1& sha1::clear() noexcept
{
    _state[0] = 0x67452301;
    _state[1] = 0xefcdab89;
    _state[2] = 0x98badcfe;
    _state[3] = 0x10325476;
    _state[4] = 0xc3d2e1f0;
    _msglen = 0;
    _hash.resize(sha1::hash_size);
    return *this;
}

template<typename fn_t>
void hash_impl(std::uint32_t state[5], std::size_t blocks, fn_t get_data)
{
    auto alice = [](std::uint32_t x, std::uint32_t y, std::uint32_t z) {
        return (x & y) | (~x & z);
    };

    auto bob = [](std::uint32_t x, std::uint32_t y, std::uint32_t z) {
        return x ^ y ^ z;
    };

    auto dave = [](std::uint32_t x, std::uint32_t y, std::uint32_t z) {
        return (x & y) | (x & z) | (y & z);
    };

    auto rotl = [](std::uint32_t val, std::uint8_t shifts) {
        return (val << shifts) | (val >> (32 - shifts));
    };

    while (blocks--) {
        std::array<std::uint32_t, 80> words;
        get_data(words, 16);
        for (std::size_t i = 16; i < 80; i++) {
            auto val = words[i - 3];
            val ^= words[i - 8];
            val ^= words[i - 14];
            val ^= words[i - 16];
            words[i] = rotl(val, 1);
        }

        std::uint32_t tmp[5] = {
            state[0], state[1], state[2], state[3], state[4]
        };

        auto update = [&](std::uint32_t val, std::uint32_t k, std::size_t i) {
            val = rotl(tmp[0], 5) + val + tmp[4] + k + words[i];
            tmp[4] = tmp[3];
            tmp[3] = tmp[2];
            tmp[2] = rotl(tmp[1], 30);
            tmp[1] = tmp[0];
            tmp[0] = val;
        };

        for (std::size_t i = 0; i < 20; i++) {
            auto val = alice(tmp[1], tmp[2], tmp[3]);
            update(val, 0x5a827999, i);
        }

        for (std::size_t i = 20; i < 40; i++) {
            auto val = bob(tmp[1], tmp[2], tmp[3]);
            update(val, 0x6ed9eba1, i);
        }

        for (std::size_t i = 40; i < 60; i++) {
            auto val = dave(tmp[1], tmp[2], tmp[3]);
            update(val, 0x8f1bbcdc, i);
        }

        for (std::size_t i = 60; i < 80; i++) {
            auto val = bob(tmp[1], tmp[2], tmp[3]);
            update(val, 0xca62c1d6, i);
        }

        state[0] += tmp[0];
        state[1] += tmp[1];
        state[2] += tmp[2];
        state[3] += tmp[3];
        state[4] += tmp[4];
    }
}

sha1& sha1::update(const std::uint8_t* data, std::size_t size) noexcept
{
    _msglen += size;
    const std::uint8_t* src;
    auto get_data = [&](auto& words, std::size_t count) {
        for (std::size_t k = 0; k < count; k++) {
            std::uint32_t val = 0;
            val |= *src++ << 24;
            val |= *src++ << 16;
            val |= *src++ << 8;
            val |= *src++;
            words[k] = val;
        }
    };

    if (_hash.size() > sha1::hash_size) {    // consume buffered data
        auto space = _hash.capacity() - _hash.size();
        std::size_t copied = size > space ? space : size;
        std::string_view tmp(reinterpret_cast<const char*>(data), copied);
        _hash.append(tmp);
        data += copied;
        size -= copied;
        if (copied == space) {      // got a full block
            src = reinterpret_cast<const std::uint8_t*>(&_hash[sha1::hash_size]);
            hash_impl(_state, 1, get_data);
            _hash.resize(sha1::hash_size);
        }
    }

    if (auto rem = size % sha1::block_size) {
        std::string_view tmp(reinterpret_cast<const char*>(data + size - rem), rem);
        _hash.append(tmp);
    }

    src = data;
    hash_impl(_state, size / sha1::block_size, get_data);
    return *this;
}

const std::string& sha1::finalize(const std::uint8_t* data, std::size_t size, std::uint8_t* dst) noexcept
{
    _msglen += size;
    if (_hash.size() > sha1::hash_size) {
        auto space = _hash.capacity() - _hash.size();
        std::size_t copied = size > space ? space : size;
        std::string_view tmp(reinterpret_cast<const char*>(data), copied);
        _hash.append(tmp);
        if (copied == space) {
            data += copied;
            size -= copied;
            auto src = reinterpret_cast<const std::uint8_t*>(&_hash[sha1::hash_size]);
            auto get_data = [&](auto& words, std::size_t count) {
                for (std::size_t k = 0; k < count; k++) {
                    std::uint32_t val = 0;
                    val |= *src++ << 24;
                    val |= *src++ << 16;
                    val |= *src++ << 8;
                    val |= *src++;
                    words[k] = val;
                }
            };
            hash_impl(_state, 1, get_data);
            _hash.resize(sha1::hash_size);
        } else {
            data = reinterpret_cast<const std::uint8_t*>(&_hash[sha1::hash_size]);
            size = _hash.size() - sha1::hash_size;
        }
    }

    std::array<std::uint8_t, 72> padding {};
    std::size_t rem = size % sha1::block_size;
    std::size_t pads = rem > 56 ? 120 - rem : 56 - rem;     // [1, 64] bytes
    pads = !pads ? sha1::block_size : pads;

    padding[0] = 0x80;
    std::size_t shifts = 56;
    std::uint64_t bit_size = _msglen * 8;
    for (std::size_t i = 0; i < 8; i++) {   // 0xffeebbaa99881100 -> ffeebbaa99881100
        padding[pads + i] = static_cast<std::uint8_t>(bit_size >> shifts);
        shifts -= 8;
    }

    std::size_t offset = 0;
    auto get_data = [&](auto& words, std::size_t count) {
        for (std::size_t k = 0; k < count; k++) {
            std::uint32_t val = 0;
            if (offset + 3 < size) {
                val |= data[offset++] << 24;
                val |= data[offset++] << 16;
                val |= data[offset++] << 8;
                val |= data[offset++];
            } else {
                const std::uint8_t* src;
                src = offset < size ? data + offset++ : &padding[offset++ - size];
                val |= *src << 24;
                src = offset < size ? data + offset++ : &padding[offset++ - size];
                val |= *src << 16;
                src = offset < size ? data + offset++ : &padding[offset++ - size];
                val |= *src << 8;
                src = offset < size ? data + offset++ : &padding[offset++ - size];
                val |= *src;
            }
            words[k] = val;
        }
    };

    std::size_t blocks = (size + pads + 8) / sha1::block_size;
    hash_impl(_state, blocks, get_data);

    static constexpr char hex_table[] = {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
    };

    offset = 0;
    for (std::size_t i = 0; i < 5; i++) {
        shifts = 24;
        auto word = _state[i];
        for (std::size_t k = 0; k < 4; k++) {
            auto val = static_cast<std::uint8_t>(word >> shifts);
            if (dst) {
                *dst++ = val;
            }
            _hash[offset++] = static_cast<char>(hex_table[val >> 4]);
            _hash[offset++] = static_cast<char>(hex_table[val & 0x0f]);
            shifts -= 8;
        }
    }

    clear();
    return _hash;
}

}
