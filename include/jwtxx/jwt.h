#pragma once

#include <functional>
#include <string>
#include <unordered_map>
#include <memory>
#include <stdexcept>

#include <ctime>

namespace JWTXX
{

void enableOpenSSLErrors();

enum class Algorithm {
    HS256, HS384, HS512,
    RS256, RS384, RS512,
    ES256, ES384, ES512,
    none
};

std::string algToString(Algorithm alg);
Algorithm stringToAlg(const std::string& value);

class Key
{
    public:
        struct Error : std::runtime_error
        {
            explicit Error(const std::string& message) : runtime_error(message) {}
        };

        Key(Algorithm alg, const std::string& keyData);
        ~Key();

        Key(Key&&);
        Key& operator=(Key&&);

        Algorithm alg() const { return m_alg; }

        std::string sign(const void* data, size_t size) const;
        bool verify(const void* data, size_t size, const std::string& signature) const;

        struct Impl;
    private:
        Algorithm m_alg;
        std::unique_ptr<Impl> m_impl;
};

class JWT
{
    public:
        typedef std::unordered_map<std::string, std::string> Pairs;
        typedef std::function<bool (const Pairs&)> Validator;

        struct Error : std::runtime_error
        {
            explicit Error(const std::string& message) : runtime_error(message) {}
        };

        JWT(const std::string& token, Key key);
        JWT(Algorithm alg, Pairs claims, Pairs header = Pairs());

        static JWT parse(const std::string& token);
        static bool verify(const std::string& token, Key key);

        Algorithm alg() const { return m_alg; }
        const Pairs& claims() const { return m_claims; }
        const Pairs& header() const { return m_header; }

        std::string claim(const std::string& name) const;

        std::string token(const std::string& keyData) const;

    private:
        Algorithm m_alg;
        Pairs m_header;
        Pairs m_claims;
};

namespace Validate
{

JWT::Validator exp(std::time_t now = std::time(nullptr));
JWT::Validator nbf(std::time_t now = std::time(nullptr));
JWT::Validator iat(std::time_t now = std::time(nullptr));
JWT::Validator iss(const std::string& issuer);
JWT::Validator aud(const std::string& audience);
JWT::Validator sub(const std::string& subject);

}

}
