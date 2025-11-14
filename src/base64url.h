#pragma once

#include "jwtxx/error.h"

#include <string>

#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/bio.h>

#include <cstring>

namespace JWTXX
{
namespace Base64URL
{

class Block
{
    public:
        Block() noexcept : m_buffer(nullptr), m_size(0) {}
        explicit Block(size_t size) noexcept : m_buffer(OPENSSL_malloc(size)), m_size(size) {}
        ~Block() { OPENSSL_free(m_buffer); }
        Block(Block&& rhs) noexcept : m_buffer(rhs.m_buffer), m_size(rhs.m_size) { rhs.m_buffer = nullptr; rhs.m_size = 0; }
        Block& operator=(Block&& rhs) noexcept { OPENSSL_free(m_buffer); m_buffer = rhs.m_buffer; m_size = rhs.m_size; rhs.m_buffer = nullptr; rhs.m_size = 0; return *this; }

        size_t size() const noexcept { return m_size; }
        const void* data() const noexcept { return m_buffer; }

        template <typename T = void*>
        T data() noexcept { return static_cast<T>(m_buffer); }

        template <typename T = void*>
        T dataAt(size_t pos)
        {
            return static_cast<uint8_t*>(m_buffer) + pos;
        }

        std::string toString() const noexcept
        {
            if (m_size == 0)
                return {};
            return std::string(static_cast<const char*>(m_buffer), m_size);
        }

        Block shrink(size_t size) noexcept { Block block(m_buffer, size); m_buffer = nullptr; m_size = 0; return block; }

        Block(const Block&) = delete;
        Block& operator=(const Block&) = delete;

        static Block zero(size_t size) { Block res(size); memset(res.data(), 0, size); return res; }
        static Block fromRaw(const void* ptr, size_t size) { Block res(size); memcpy(res.data(), ptr, size); return res; }

    private:
        void* m_buffer;
        size_t m_size;

        Block(void* buffer, size_t size) noexcept : m_buffer(buffer), m_size(size) {}
};

inline
std::string URLEncode(const std::string& data) noexcept
{
    if (data.empty())
        return {};

    std::string res;
    res.reserve(data.size());
    for (const auto& ch : data)
    {
        if (ch == '=')
            continue;
        else if (ch == '/')
            res += '_';
        else if (ch == '+')
            res += '-';
        else
            res += ch;
    }
    return res;
}

inline
std::string URLDecode(const std::string& data) noexcept
{
    if (data.empty())
        return {};

    std::string res;
    res.reserve(data.size());
    for (const auto& ch : data)
    {
        if (ch == '_')
            res += '/';
        else if (ch == '-')
            res += '+';
        else
            res += ch;
    }

    if (res.size() % 4 == 2)
        return res + "==";
    else if (res.size() % 4 == 3)
        return res + "=";

    return res;
}

inline
std::string encode(const Block& block)
{
    BIO* bio = BIO_push(BIO_new(BIO_f_base64()), BIO_new(BIO_s_mem()));
    if (bio == nullptr)
        throw Error("Base64URL: cannot allocate base64 encoder.");
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    const auto rv = BIO_write(bio, block.data(), block.size());
    if (rv < 0)
    {
        BIO_free_all(bio);
        throw Error("Base64URL: cannot encode input data.");
    }

    std::string res;

    if (BIO_flush(bio) == 1)
    {
        char* buf = nullptr;
        size_t size = BIO_get_mem_data(bio, &buf);
        if (size != 0 && buf != nullptr)
            res.assign(buf, size);
    }

    BIO_free_all(bio);

    return URLEncode(res);
}

inline
std::string encode(const std::string& data)
{
    Block block(data.size());
    memcpy(block.data(), data.c_str(), data.size());
    return encode(block);
}

inline
Block decode(std::string data)
{
    data = URLDecode(data);

    BIO* bio = BIO_push(BIO_new(BIO_f_base64()), BIO_new_mem_buf(const_cast<char*>(data.c_str()), data.size()));
    if (bio == nullptr)
        throw Error("Base64URL: cannot allocate base64 decoder.");
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    Block block(data.size());
    const auto rv = BIO_read(bio, block.data(), block.size());
    if (rv < 0)
    {
        BIO_free_all(bio);
        throw Error("Base64URL: cannot decode input data.");
    }
    BIO_free_all(bio);

    return block.shrink(rv);
}

}
}
