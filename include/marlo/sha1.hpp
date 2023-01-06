#pragma once

#include <cstdint>
#include <string>

namespace marlo {

class sha1 {
public:
    sha1();

    sha1& clear() noexcept;
    sha1& update(std::string_view bytes) noexcept;
    sha1& update(const std::uint8_t* data, std::size_t size) noexcept;
    const std::string& finalize(std::string_view bytes, std::string& dst);
    const std::string& finalize(std::string_view bytes, std::uint8_t* dst = nullptr) noexcept;
    const std::string& finalize(const std::uint8_t* data, std::size_t size, std::string& dst);
    const std::string& finalize(const std::uint8_t* data, std::size_t size, std::uint8_t* dst = nullptr) noexcept;

    static std::string eval(std::string_view bytes);

    static constexpr std::size_t bit_size = 160;
    static constexpr std::size_t block_size = 64;
    static constexpr std::size_t hash_size = 40;

private:
    std::uint32_t _state[5];
    std::uint64_t _msglen;
    std::string _hash;
};

inline sha1& sha1::update(std::string_view bytes) noexcept
{
    return update(reinterpret_cast<const std::uint8_t*>(bytes.data()), bytes.size());
}

inline const std::string& sha1::finalize(std::string_view bytes, std::string& dst)
{
    auto old_size = dst.size();
    dst.resize(old_size + sha1::bit_size / 8);
    return finalize(bytes, reinterpret_cast<std::uint8_t*>(&dst[old_size]));
}

inline const std::string& sha1::finalize(std::string_view bytes, std::uint8_t* dst) noexcept
{
    return finalize(reinterpret_cast<const std::uint8_t*>(bytes.data()), bytes.size(), dst);
}

inline const std::string& sha1::finalize(const std::uint8_t* data, std::size_t size, std::string& dst)
{
    auto old_size = dst.size();
    dst.resize(old_size + sha1::bit_size / 8);
    return finalize(data, size, reinterpret_cast<std::uint8_t*>(&dst[old_size]));
}

inline std::string sha1::eval(std::string_view bytes)
{
    return sha1().finalize(bytes);
}

}
