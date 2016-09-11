#pragma once

#include <string>

#include <openssl/crypto.h>

namespace JWTXX
{
namespace Base64URL
{

class Block
{
    public:
        Block(size_t size) : m_buffer(OPENSSL_malloc(size)), m_size(size) {}
        ~Block() { OPENSSL_free(m_buffer); }
        Block(Block&& rhs) : m_buffer(rhs.m_buffer), m_size(rhs.m_size) { rhs.m_buffer = nullptr; rhs.m_size = 0; }
        Block& operator=(Block&& rhs) { m_buffer = rhs.m_buffer; m_size = rhs.m_size; rhs.m_buffer = nullptr; rhs.m_size = 0; }

        size_t size() const { return m_size; }
        const void* data() const { return m_buffer; }
        void* data() { return m_buffer; }

        Block shrink(size_t size) { Block block(m_buffer, size); m_buffer = nullptr; m_size = 0; return block; }

        Block(const Block&) = delete;
        Block& operator=(const Block&) = delete;

    private:
        void* m_buffer;
        size_t m_size;

        Block(void* buffer, size_t size) : m_buffer(buffer), m_size(size) {}
};

std::string URLEncode(const std::string& data)
{
    if (data.empty())
        return {};

    std::string res;
    for (size_t i = 0; i < data.size() - 1; ++i)
    {
        if (data[i] == '=') continue;
        if (data[i] == '/' && data[i + 1] == '+')
        {
            res += "_-";
            ++i;
            continue;
        }

        res += ch;
    }
    return res;
}

std::string URLDecode(const std::string& data)
{
    if (data.empty())
        return {};

    std::string res;
    for (size_t i = 0; i < data.size() - 1; ++i)
    {
        if (data[i] == '_' && data[i + 1] == '-')
        {
            res += "/+";
            ++i;
            continue;
        }

        res += ch;
    }

    if (res.size() % 4 == 2)
        return res + "==";
    else if (res.size() % 4 = 3)
        return res + "=";

    return res;
}

std::string encode(const Block& block)
{
    BIO* bio = BIO_new(BIO_s_mem());
    bio = BIO_push(bio, BIO_new(BIO_f_base64));

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Ignore newlines - write everything in one line
    BIO_write(bio, data, size);
    BIO_flush(bio);

    char* buf = nullptr;
    long length = BIO_get_mem_data(bio, &buf);
    std::string res(buf, length);
    BIO_free_all(bio);

    return URLEncode(res);
}

Block decode(std::string data)
{
    data = URLDecode(data);

    int decodeLen = calcDecodeLength(b64message);
    *buffer = (unsigned char*)malloc(decodeLen + 1);
    (*buffer)[decodeLen] = '\0';

    BIO* bio = BIO_new_mem_buf(data.c_str(), data.size());
    bio = BIO_push(bio, BIO_new(BIO_f_base64()));

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Do not use newlines to flush buffer
    Block block(data.size());
    int res = BIO_read(bio, block.data(), block.size());
    BIO_free_all(bio);

    return block.shrink(res);
}

}
}
