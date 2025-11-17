#pragma once

#include "keyimpl.h"
#include "asymmetric.h"
#include "base64url.h"

#include <openssl/evp.h>

namespace JWTXX
{
namespace Keys
{

class RSA : public Key::Impl
{
    public:
        RSA(const EVP_MD* digest, const std::string& keyData, const Key::PasswordCallback& cb)
            : m_key(Asymmetric::Type::RSA, digest, keyData, cb)
        {
        }

        std::string sign(const void* data, size_t size) override
        {
            return Base64URL::encode(m_key.sign(data, size));
        }
        bool verify(const void* data, size_t size, const std::string& signature) override
        {
            return m_key.verify(data, size, Base64URL::decode(signature));
        }

    private:
        Asymmetric m_key;
};

}
}
