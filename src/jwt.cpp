#include "jwtxx/jwt.h"

#include "keyimpl.h"
#include "hmackey.h"
#include "rsakey.h"
#include "eckey.h"
#include "utils.h"

using JWTXX::Algorithm;
using JWTXX::Key;
using JWTXX::JWT;

namespace Keys = JWTXX::Keys;

namespace
{

struct NoneKey : public Key::Impl
{
    std::string sign(const void* /*data*/, size_t /*size*/) const override { return {}; }
    bool verify(const void* /*data*/, size_t /*size*/, const std::string& /*signature*/) const override { return true; }
};

Key::Impl* createKey(Algorithm alg, const std::string& keyData)
{
    switch (alg)
    {
        case Algorithm::none: return new NoneKey;
        case Algorithm::HS256: return new Keys::HMAC(EVP_sha256(), keyData);
        case Algorithm::HS384: return new Keys::HMAC(EVP_sha384(), keyData);
        case Algorithm::HS512: return new Keys::HMAC(EVP_sha512(), keyData);
        case Algorithm::RS256: return new Keys::RSA(EVP_sha256(), keyData);
        case Algorithm::RS384: return new Keys::RSA(EVP_sha384(), keyData);
        case Algorithm::RS512: return new Keys::RSA(EVP_sha512(), keyData);
        case Algorithm::ES256: return new Keys::EC(EVP_sha256(), keyData);
        case Algorithm::ES384: return new Keys::EC(EVP_sha384(), keyData);
        case Algorithm::ES512: return new Keys::EC(EVP_sha512(), keyData);
    }
    return new NoneKey; // Just in case.
}

}

Key::Key(Algorithm alg, const std::string& keyData)
    : m_impl(createKey(alg, keyData))
{
}

std::string Key::sign(const void* data, size_t size) const
{
    return m_impl->sign(data, size);
}

bool Key::verify(const void* data, size_t size, const std::string& signature) const
{
    return m_impl->verify(data, size, signature);
}
