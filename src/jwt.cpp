#include "jwtxx/jwt.h"

#include "keyimpl.h"
#include "hmackey.h"
#include "rsakey.h"
#include "eckey.h"
#include "base64url.h"
#include "utils.h"
#include "json.h"

#include <boost/algorithm/string/split.hpp>

#include <openssl/evp.h>
#include <openssl/err.h>

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

void JWTXX::enableOpenSSLErrors()
{
    static bool enabled = [](){ OpenSSL_add_all_algorithms(); ERR_load_crypto_strings(); return true; }();
}

std::string JWTXX::algToString(Algorithm alg)
{
    switch (alg)
    {
        case Algorithm::none: return "none";
        case Algorithm::HS256: return "HS256";
        case Algorithm::HS384: return "HS384";
        case Algorithm::HS512: return "HS512";
        case Algorithm::RS256: return "RS256";
        case Algorithm::RS384: return "RS384";
        case Algorithm::RS512: return "RS512";
        case Algorithm::ES256: return "ES256";
        case Algorithm::ES384: return "ES384";
        case Algorithm::ES512: return "ES512";
    }
    return ""; // Just in case.
}

Algorithm JWTXX::stringToAlg(const std::string& value)
{
    if (value == "none") return Algorithm::none;
    else if (value == "HS256") return Algorithm::HS256;
    else if (value == "HS384") return Algorithm::HS384;
    else if (value == "HS512") return Algorithm::HS512;
    else if (value == "RS256") return Algorithm::RS256;
    else if (value == "RS384") return Algorithm::RS384;
    else if (value == "RS512") return Algorithm::RS512;
    else if (value == "ES256") return Algorithm::ES256;
    else if (value == "ES384") return Algorithm::ES384;
    else if (value == "ES512") return Algorithm::ES512;
    else throw std::runtime_error("Invalid algorithm name: '" + value + "'.");
}

Key::Key(Algorithm alg, const std::string& keyData)
    : m_alg(alg), m_impl(createKey(alg, keyData))
{
}

Key::~Key() = default;
Key::Key(Key&&) = default;
Key& Key::operator=(Key&&) = default;

std::string Key::sign(const void* data, size_t size) const
{
    return m_impl->sign(data, size);
}

bool Key::verify(const void* data, size_t size, const std::string& signature) const
{
    return m_impl->verify(data, size, signature);
}

JWT::JWT(Algorithm alg, Pairs claims, Pairs header)
    : m_alg(alg), m_header(header), m_claims(claims)
{
    m_header["typ"] = "JWT";
    m_header["alg"] = algToString(m_alg);
}

JWT::JWT(const std::string& token, Key key)
{
    std::vector<std::string> parts;
    boost::split(parts, token, [](char ch){ return ch == '.'; });
    if (parts.size() < 2 || parts.size() > 3)
        throw Error("JWT should contain only 2 or 3 parts. The supplied token contains " + std::to_string(parts.size()) + " parts.");
    auto data = parts[0] + "." + parts[1];
    std::string signature;
    if (parts.size() == 3)
        signature = parts[2];
    if (!key.verify(data.c_str(), data.size(), signature))
        throw Error("Signature is invalid.");
    m_alg = key.alg();
    m_header = fromJSON(Base64URL::decode(parts[0]).toString());
    m_claims = fromJSON(Base64URL::decode(parts[1]).toString());
}

std::string JWT::claim(const std::string& name) const
{
    auto it = m_claims.find(name);
    if (it == std::end(m_claims))
        return {};
    return it->second;
}

std::string JWT::token(const std::string& keyData) const
{
    auto data = Base64URL::encode(toJSON(m_header)) + "." + Base64URL::encode(toJSON(m_claims));
    Key key(m_alg, keyData);
    auto signature = key.sign(data.c_str(), data.size());
    if (signature.empty())
        return data;
    return data + "." + signature;
}
