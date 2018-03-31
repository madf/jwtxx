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
            : m_data(keyData), m_cb(cb), m_digest(digest)
        {
        }

        std::string sign(const void* data, size_t size) const override
        {
            return Base64URL::encode(signImpl(Utils::readPEMPrivateKey(m_data, m_cb), data, size));
        }
        bool verify(const void* data, size_t size, const std::string& signature) const override
        {
            return verifyImpl(Utils::readPEMPublicKey(m_data), data, size, Base64URL::decode(signature));
        }
    protected:
        std::string m_data;
        Key::PasswordCallback m_cb;

        Base64URL::Block signImpl(const Utils::EVPKeyPtr& key, const void* data, size_t size) const
        {
            auto ctx = initCTX();
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
            return block.shrink(res);
        }

        bool verifyImpl(const Utils::EVPKeyPtr& key, const void* data, size_t size, Base64URL::Block signature) const
        {
            auto ctx = initCTX();
            if (EVP_DigestVerifyInit(ctx.get(), nullptr, m_digest, nullptr, key.get()) != 1)
                throw Key::Error("Can't init verification context. " + Utils::OPENSSLError());
            if (EVP_DigestVerifyUpdate(ctx.get(), data, size) != 1)
                throw Key::Error("Can't add data to verification. " + Utils::OPENSSLError());
            return EVP_DigestVerifyFinal(ctx.get(), signature.data<unsigned char*>(), signature.size()) == 1;
        }
    private:
        const EVP_MD* m_digest;

        Utils::EVPMDCTXPtr initCTX() const
        {
            Utils::EVPMDCTXPtr ctx(EVP_MD_CTX_create());
            if (!ctx)
                throw Key::Error("Can't create context. " + Utils::OPENSSLError());
            if (EVP_DigestInit_ex(ctx.get(), m_digest, nullptr) != 1)
                throw Key::Error("Can't initialize context. " + Utils::OPENSSLError());
            return ctx;
        }
};

}
}
