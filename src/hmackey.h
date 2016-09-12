#pragma once

#include "keyimpl.h"
#include "utils.h"
#include "base64url.h"

#include <openssl/evp.h>

namespace JWTXX
{
namespace Keys
{

class HMAC : public Key::Impl
{
    public:
        HMAC(const EVP_MD* digest, const std::string& keyData)
            : m_digest(digest), m_data(keyData)
        {
        }

        std::string sign(const void* data, size_t size) const override
        {
            Utils::EVPMDCTXPtr ctx(EVP_MD_CTX_create());
            if (!ctx)
                throw Key::Error("Can't create sign context. " + Utils::OPENSSLError());
            if (EVP_DigestInit_ex(ctx.get(), m_digest, nullptr) != 1)
                throw Key::Error("Can't init sign context. " + Utils::OPENSSLError());
            Utils::EVPKeyPtr key(EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, nullptr,
                                 reinterpret_cast<const unsigned char*>(m_data.c_str()), m_data.size()));
            if (!key)
                throw Key::Error("Can't create HMAC key. " + Utils::OPENSSLError());
            if (EVP_DigestSignInit(ctx.get(), nullptr, m_digest, nullptr, key.get()) != 1)
                throw Key::Error("Can't init sign context. " + Utils::OPENSSLError());
            if (EVP_DigestSignUpdate(ctx.get(), data, size) != 1)
                throw Key::Error("Can't sign data. " + Utils::OPENSSLError());
            size_t res = 0;
            if (EVP_DigestSignFinal(ctx.get(), nullptr, &res) != 1)
                throw Key::Error("Can't sign data. " + Utils::OPENSSLError());
            if (res == 0)
                return {};
            Base64URL::Block block(res);
            if (EVP_DigestSignFinal(ctx.get(), block.data<unsigned char*>(), &res) != 1)
                throw Key::Error("Can't sign data. " + Utils::OPENSSLError());
            return Base64URL::encode(block);
        }
        bool verify(const void* data, size_t size, const std::string& signature) const override
        {
            return sign(data, size) == signature;
        }
    private:
        const EVP_MD* m_digest;
        std::string m_data;
};

}
}
