#include "jwtxx/jwt.h"

#include "keyimpl.h"
#include "hmackey.h"
#include "pemkey.h"
#include "base64url.h"
#include "utils.h"
#include "json.h"

#include <vector>
#include <utility> // std::move

#include <ctime>

#include <openssl/evp.h>
#include <openssl/err.h>

using JWTXX::Algorithm;
using JWTXX::Validator;
using JWTXX::Pairs;
using JWTXX::Key;
using JWTXX::JWT;

namespace Keys = JWTXX::Keys;
namespace Validate = JWTXX::Validate;

namespace
{

struct NoneKey : public Key::Impl
{
    std::string sign(const void* /*data*/, size_t /*size*/) const override
    {
        return {};
    }
    bool verify(const void* /*data*/, size_t /*size*/,
                const std::string& /*signature*/) const override
    {
        return true;
    }
};

Key::Impl* createKey(Algorithm alg, const std::string& keyData, const Key::PasswordCallback& cb) noexcept
{
    switch (alg)
    {
        case Algorithm::none: return new NoneKey;
        case Algorithm::HS256: return new Keys::HMAC(EVP_sha256(), keyData);
        case Algorithm::HS384: return new Keys::HMAC(EVP_sha384(), keyData);
        case Algorithm::HS512: return new Keys::HMAC(EVP_sha512(), keyData);
        case Algorithm::RS256: return new Keys::PEM(EVP_sha256(), keyData, cb);
        case Algorithm::RS384: return new Keys::PEM(EVP_sha384(), keyData, cb);
        case Algorithm::RS512: return new Keys::PEM(EVP_sha512(), keyData, cb);
        case Algorithm::ES256: return new Keys::PEM(EVP_sha256(), keyData, cb);
        case Algorithm::ES384: return new Keys::PEM(EVP_sha384(), keyData, cb);
        case Algorithm::ES512: return new Keys::PEM(EVP_sha512(), keyData, cb);
    }
    return new NoneKey; // Just in case.
}

template <typename F>
JWTXX::ValidationResult validTime(const std::string& value, F&& next) noexcept
{
    try
    {
        size_t pos = 0;
        auto t = std::stoull(value, &pos);
        if (pos != value.length())
            return JWTXX::ValidationResult::failure("Invalid time value. Should be a positive integer value, got '" + value + "'.");
        return next(t);
    }
    catch (const std::logic_error&)
    {
        return JWTXX::ValidationResult::failure("Invalid time value. Should be a positive integer value, got '" + value + "'.");
    }
}

template <typename F>
JWTXX::ValidationResult validClaim(const Pairs& claims, std::string claim, F&& next) noexcept
{
    auto it = claims.find(claim);
    if (it == std::end(claims))
        return JWTXX::ValidationResult::ok();
    return next(it->second);
}

template <typename F>
JWTXX::ValidationResult validTimeClaim(const Pairs& claims, std::string claim, F&& next) noexcept
{
    return validClaim(claims, std::move(claim),
                      [&](const std::string& value)
                      {
                          return validTime(value, std::move(next));
                      });
}

Validator stringValidator(std::string&& name,
                          std::string&& validValue) noexcept
{
    return [=](const Pairs& claims)
           {
               return validClaim(claims, std::move(name),
                                 [=](const std::string& value)
                                 {
                                     return value == validValue ? JWTXX::ValidationResult::ok() : JWTXX::ValidationResult::failure("'" + name + "' claim should be '" + validValue + "'. Got: '" + value + "'.");
                                 });
           };
}

std::string formatTime(std::time_t value) noexcept
{
    std::tm tmb;
    char buf[20];
    gmtime_r(&value, &tmb);
    auto res = std::strftime(buf, sizeof(buf), "%F %T", &tmb);
    if (res == 0)
        return "<" + std::to_string(value) + ">";
    return std::string(buf, res);
}

}

void JWTXX::enableOpenSSLErrors() noexcept
{
    struct OpenSSLErrors
    {
        OpenSSLErrors() noexcept { ERR_load_crypto_strings(); OpenSSL_add_all_algorithms(); }
        ~OpenSSLErrors() { EVP_cleanup(); ERR_free_strings(); CRYPTO_cleanup_all_ex_data(); }
    };
    static const OpenSSLErrors enabled __attribute__((used));
}

std::string JWTXX::algToString(Algorithm alg) noexcept
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
    else throw JWT::ParseError("Invalid algorithm name: '" + value + "'.");
}

Key::Key(Algorithm alg, const std::string& keyData, const PasswordCallback& cb) noexcept
    : m_alg(alg), m_impl(createKey(alg, keyData, cb))
{
}

Key::~Key() = default;
Key::Key(Key&&) noexcept = default;
Key& Key::operator=(Key&&) noexcept = default;

std::string Key::sign(const void* data, size_t size) const
{
    return m_impl->sign(data, size);
}

bool Key::verify(const void* data, size_t size,
                 const std::string& signature) const
{
    return m_impl->verify(data, size, signature);
}

std::string Key::noPasswordCallback()
{
    throw Utils::PasswordCallbackError();
}

JWT::JWT(Algorithm alg, Pairs claims, Pairs header) noexcept
    : m_alg(alg), m_header(header), m_claims(claims)
{
    m_header["typ"] = "JWT";
    m_header["alg"] = algToString(m_alg);
}

JWT::JWT(const std::string& token, Key key, JWTXX::Validators&& validators)
{
    // Check structure in general - split parts.
    auto parts = Utils::split(token);

    // Check internal structure. fromJSON will throw on non-JSON or non-object.
    m_header = fromJSON(Base64URL::decode(std::get<0>(parts)).toString());
    m_claims = fromJSON(Base64URL::decode(std::get<1>(parts)).toString());

    auto algName = algToString(key.alg());
    if (m_header["alg"] != algName)
        throw ValidationError("\"alg\" should be \"" + algName + "\". Actual value: \"" + m_header["alg"] + "\".");

    auto data = std::get<0>(parts) + "." + std::get<1>(parts);
    if (!key.verify(data.c_str(), data.size(), std::get<2>(parts)))
        throw ValidationError("Signature is invalid.");
    m_alg = key.alg();
    for (const auto& validator : validators)
    {
        auto res = validator(m_claims);
        if (!res)
            throw ValidationError(res.message());
    }
}

JWT JWT::parse(const std::string& token)
{
    auto parts = Utils::split(token);
    Pairs header = fromJSON(Base64URL::decode(std::get<0>(parts)).toString());
    Pairs claims = fromJSON(Base64URL::decode(std::get<1>(parts)).toString());
    Algorithm alg = Algorithm::none;
    if (!header["alg"].empty())
        alg = stringToAlg(header["alg"]);
    return JWT(alg, claims, header);
}

JWTXX::ValidationResult JWT::verify(const std::string& token, Key key, JWTXX::Validators&& validators) noexcept
{
    try
    {
        auto parts = Utils::split(token);
        auto data = std::get<0>(parts) + "." + std::get<1>(parts);
        Pairs header = fromJSON(Base64URL::decode(std::get<0>(parts)).toString());
        Pairs claims = fromJSON(Base64URL::decode(std::get<1>(parts)).toString());
        auto algName = algToString(key.alg());
        if (header["alg"] != algName)
            return ValidationResult::failure("\"alg\" should be \"" + algName + "\". Actual value: \"" + header["alg"] + "\".");
        if (!key.verify(data.c_str(), data.size(), std::get<2>(parts)))
            return ValidationResult::failure("Signature is invalid.");
        for (const auto& validator : validators)
        {
            auto res = validator(claims);
            if (!res)
                return res;
        }
        return ValidationResult::ok();
    }
    catch (const JWT::ParseError& error)
    {
        return ValidationResult::failure(error.what());
    }
}

std::string JWT::claim(const std::string& name) const noexcept
{
    auto it = m_claims.find(name);
    if (it == std::end(m_claims))
        return {};
    return it->second;
}

std::string JWT::token(const std::string& keyData, const Key::PasswordCallback& cb) const
{
    auto data = Base64URL::encode(toJSON(m_header)) + "." +
                Base64URL::encode(toJSON(m_claims));
    Key key(m_alg, keyData, cb);
    auto signature = key.sign(data.c_str(), data.size());
    if (signature.empty())
        return data;
    return data + "." + signature;
}

Validator Validate::exp(std::time_t now) noexcept
{
    return [=](const Pairs& claims)
           {
               return validTimeClaim(claims, "exp",
                                     [=](std::time_t value)
                                     {
                                         return value > now ? ValidationResult::ok() : ValidationResult::failure("Token expired. Current time: '" + formatTime(now) + "', expiration time: '" + formatTime(value) + "'.");
                                     });
           };
}

Validator Validate::nbf(std::time_t now) noexcept
{
    return [=](const Pairs& claims)
           {
               return validTimeClaim(claims, "nbf",
                                     [=](std::time_t value)
                                     {
                                         return value < now ? ValidationResult::ok() : ValidationResult::failure("Token is not valid yet. Current time: '" + formatTime(now) + "', valid after: '" + formatTime(value) + "'.");
                                     });
           };
}

Validator Validate::iat(std::time_t now) noexcept
{
    return [=](const Pairs& claims)
           {
               return validTimeClaim(claims, "iat",
                                     [=](std::time_t value)
                                     {
                                         return value < now ? ValidationResult::ok() : ValidationResult::failure("Token is not issued yet. Current time: '" + formatTime(now) + "', issued at: '" + formatTime(value) + "'.");
                                     });
           };
}

Validator Validate::iss(std::string issuer) noexcept
{
    return stringValidator("iss", std::move(issuer));
}

Validator Validate::aud(std::string audience) noexcept
{
    return stringValidator("aud", std::move(audience));
}

Validator Validate::sub(std::string subject) noexcept
{
    return stringValidator("sub", std::move(subject));
}
