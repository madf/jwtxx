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
        PEM(const EVP_MD* digest, const std::string& keyData)
            : m_digest(digest), m_data(keyData)
        {
        }

        std::string sign(const void* data, size_t size) const override
        {
            auto ctx = initCTX();
            auto key = Utils::readPEMPrivateKey(m_data);
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
            return Base64URL::encode(block.shrink(res));
        }
        bool verify(const void* data, size_t size, const std::string& signature) const override
        {
            auto ctx = initCTX();
            auto key = Utils::readPEMPublicKey(m_data);
            if (EVP_DigestVerifyInit(ctx.get(), nullptr, m_digest, nullptr, key.get()) != 1)
                throw Key::Error("Can't init verification context. " + Utils::OPENSSLError());
            if (EVP_DigestVerifyUpdate(ctx.get(), data, size) != 1)
                throw Key::Error("Can't add data to verification. " + Utils::OPENSSLError());
            auto block(Base64URL::decode(signature));
            return EVP_DigestVerifyFinal(ctx.get(), block.data<unsigned char*>(), block.size()) == 1;
        }
    private:
        const EVP_MD* m_digest;
        std::string m_data;

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
