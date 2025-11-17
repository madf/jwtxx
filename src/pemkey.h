#pragma once

#include "keyimpl.h"
#include "utils.h"
#include "base64url.h"

#include <openssl/evp.h>

namespace JWTXX
{
namespace Keys
{

class PEM : public Key::Impl
{
    public:
        PEM(const EVP_MD* digest, const std::string& keyData, const Key::PasswordCallback& cb) noexcept
            : m_data(keyData), m_cb(cb), m_digest(digest), m_ctx(EVP_MD_CTX_create())
        {
            if (!m_ctx)
                throw Key::Error("Can't create context. " + Utils::OPENSSLError());
        }

        std::string sign(const void* data, size_t size) override
        {
            return Base64URL::encode(signImpl(getPrivKey("RSA"), data, size));
        }
        bool verify(const void* data, size_t size, const std::string& signature) override
        {
            return verifyImpl(getPubKey("RSA"), data, size, Base64URL::decode(signature));
        }
    protected:
        std::string m_data;
        Key::PasswordCallback m_cb;

        Base64URL::Block signImpl(const Utils::EVPKeyPtr& key, const void* data, size_t size) const
        {
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

        bool verifyImpl(const Utils::EVPKeyPtr& key, const void* data, size_t size, Base64URL::Block signature) const
        {
            if (EVP_DigestVerifyInit(m_ctx.get(), nullptr, m_digest, nullptr, key.get()) != 1)
                throw Key::Error("Can't init verification context. " + Utils::OPENSSLError());
            if (EVP_DigestVerifyUpdate(m_ctx.get(), data, size) != 1)
                throw Key::Error("Can't add data to verification. " + Utils::OPENSSLError());
            return EVP_DigestVerifyFinal(m_ctx.get(), signature.data<unsigned char*>(), signature.size()) == 1;
        }

        Utils::EVPKeyPtr& getPubKey(const char* keyType)
        {
            if (!m_pubKeyPtr)
                m_pubKeyPtr = Utils::readPEMPublicKey(m_data, keyType);
            return m_pubKeyPtr;
        }

        Utils::EVPKeyPtr& getPrivKey(const char* keyType)
        {
            if (!m_privKeyPtr)
                m_privKeyPtr = Utils::readPEMPrivateKey(m_data, m_cb, keyType);
            return m_privKeyPtr;
        }
    private:
        const EVP_MD* m_digest;
        Utils::EVPKeyPtr m_pubKeyPtr;
        Utils::EVPKeyPtr m_privKeyPtr;
        Utils::EVPMDCTXPtr m_ctx;
};

}
}
