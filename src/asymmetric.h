#pragma once

#include "utils.h"

#include <openssl/evp.h>

namespace JWTXX
{
namespace Keys
{

class Asymmetric
{
    public:
        enum class Type {RSA, EC};

        Asymmetric(Type type, const EVP_MD* digest, const std::string& keyData, const Key::PasswordCallback& cb)
            : m_type(type), m_digest(digest), m_data(keyData), m_cb(cb), m_ctx(EVP_MD_CTX_create())
        {
            if (!m_ctx)
                throw Key::Error("Can't create message digest context. " + Utils::OPENSSLError());
        }

        Base64URL::Block sign(const void* data, size_t size)
        {
            auto& key = getPrivKey();
            if (EVP_DigestSignInit(m_ctx.get(), nullptr, m_digest, nullptr, key.get()) != 1)
                throw Key::Error("Can't init sign context. " + Utils::OPENSSLError());
            if (EVP_DigestSignUpdate(m_ctx.get(), data, size) != 1)
                throw Key::Error("Can't sign data. " + Utils::OPENSSLError());
            size_t res = 0;
            if (EVP_DigestSignFinal(m_ctx.get(), nullptr, &res) != 1)
                throw Key::Error("Can't sign data. " + Utils::OPENSSLError());
            if (res == 0)
                return {};
            Base64URL::Block block(res);
            if (EVP_DigestSignFinal(m_ctx.get(), block.data<unsigned char*>(), &res) != 1)
                throw Key::Error("Can't sign data. " + Utils::OPENSSLError());
            return block.shrink(res);
        }

        bool verify(const void* data, size_t size, Base64URL::Block signature)
        {
            auto& key = getPubKey();
            if (EVP_DigestVerifyInit(m_ctx.get(), nullptr, m_digest, nullptr, key.get()) != 1)
                throw Key::Error("Can't init verification context. " + Utils::OPENSSLError());
            if (EVP_DigestVerifyUpdate(m_ctx.get(), data, size) != 1)
                throw Key::Error("Can't add data to verification. " + Utils::OPENSSLError());
            auto rv = EVP_DigestVerifyFinal(m_ctx.get(), signature.data<unsigned char*>(), signature.size());
            if (rv == 1) return true;
            if (rv == 0) return false;
            throw Key::Error("Can't verify signature. " + Utils::OPENSSLError());
        }

        Utils::EVPKeyPtr& getPubKey()
        {
            if (!m_pubKeyPtr)
                m_pubKeyPtr = Utils::readPEMPublicKey(m_data, typeName());
            return m_pubKeyPtr;
        }

        Utils::EVPKeyPtr& getPrivKey()
        {
            if (!m_privKeyPtr)
                m_privKeyPtr = Utils::readPEMPrivateKey(m_data, m_cb, typeName());
            return m_privKeyPtr;
        }

    private:
        Type m_type;
        const EVP_MD* m_digest;
        std::string m_data;
        Key::PasswordCallback m_cb;
        Utils::EVPKeyPtr m_pubKeyPtr;
        Utils::EVPKeyPtr m_privKeyPtr;
        Utils::EVPMDCTXPtr m_ctx;

        const char* typeName() const noexcept
        {
            switch (m_type) {
                case Type::RSA: return "RSA";
                case Type::EC:  return "EC";
            };
            return "";
        }
};

}
}
