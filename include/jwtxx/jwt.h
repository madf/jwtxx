#pragma once

#include <string>
#include <unordered_map>
#include <memory>
#include <stdexcept>

namespace JWTXX
{

enum class Algorithm {
    HS256, HS384, HS512,
    RS256, RS384, RS512,
    ES256, ES384, ES512,
    none
};

class Key
{
    public:
        struct Error : std::runtime_error
        {
            Error(const std::string& message) : runtime_error(message) {}
        };

        Key(Algorithm alg, const std::string& keyData);

        std::string sign(const void* data, size_t size) const;
        bool verify(const void* data, size_t size, const std::string& signature) const;

        struct Impl;
    private:
        std::unique_ptr<Impl> m_impl;
};

class JWT
{
    public:
        typedef std::unordered_map<std::string, std::string> Pairs;

        JWT(const std::string& token, Key key);
        JWT(Algorithm alg, Pairs claims, Pairs header = Pairs());

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

}
