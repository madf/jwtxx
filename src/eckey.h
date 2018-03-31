#pragma once

#include "pemkey.h"

#include <openssl/ecdsa.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>

namespace JWTXX
{
namespace Keys
{

class EC : public PEM
{
    public:
        EC(const EVP_MD* digest, const std::string& keyData, const Key::PasswordCallback& cb) noexcept
            : PEM(digest, keyData, cb)
        {
        }

        std::string sign(const void* data, size_t size) const override
        {
            auto key = Utils::readPEMPrivateKey(m_data, m_cb);
            return Base64URL::encode(unpack(primeSize(key), signImpl(key, data, size)));
        }

        bool verify(const void* data, size_t size, const std::string& signature) const override
        {
            auto key = Utils::readPEMPublicKey(m_data);
            return verifyImpl(key, data, size, pack(primeSize(key), Base64URL::decode(signature)));
        }
    private:
        struct SigDeleter
        {
            void operator()(ECDSA_SIG* ptr) { ECDSA_SIG_free(ptr); }
        };
        using SigPtr = std::unique_ptr<ECDSA_SIG, SigDeleter>;
        static Base64URL::Block unpack(size_t pSize, Base64URL::Block src)
        {
            // Unpack data
            auto srcSig = src.data<const unsigned char*>();
            SigPtr sig(d2i_ECDSA_SIG(nullptr, &srcSig, src.size()));
            if (sig == nullptr)
                throw Key::Error("Can't unpack DER-encoded signature. " + Utils::OPENSSLError());

            // Check sizes
            auto rSize = static_cast<size_t>(BN_num_bytes(sig.get()->r));
            auto sSize = static_cast<size_t>(BN_num_bytes(sig.get()->s));
            if (rSize > pSize || sSize > pSize)
                throw Key::Error("Signature param sizes are inconsistent with the field prime size (p: " + std::to_string(pSize) + ", r: " + std::to_string(rSize) + ", s: " + std::to_string(sSize) + ").");

            // Put them raw, leading zeros
            auto dest = Base64URL::Block::zero(pSize * 2);
            BN_bn2bin(sig.get()->r, dest.dataAt<unsigned char*>(pSize - rSize));
            BN_bn2bin(sig.get()->s, dest.dataAt<unsigned char*>(pSize * 2 - rSize));
            return dest;
        }
        static Base64URL::Block pack(size_t pSize, Base64URL::Block src)
        {
            // Broken signature here is a validation error
            if (src.size() != pSize * 2)
                throw JWT::ValidationError("Signature size is inconsistent with the field prime size (p: " + std::to_string(pSize) + ", 2p: " + std::to_string(pSize * 2) + ", s: " + std::to_string(src.size()) + ").");

            auto r = BN_bin2bn(src.data<const unsigned char*>(), pSize, nullptr);
            auto s = BN_bin2bn(src.dataAt<const unsigned char*>(pSize), pSize, nullptr);

            SigPtr sig(ECDSA_SIG_new());
            BN_free(sig.get()->r);
            BN_free(sig.get()->s);
            sig.get()->r = r;
            sig.get()->s = s;

            auto sigSize = i2d_ECDSA_SIG(sig.get(), nullptr);
            if (sigSize <= 0)
                throw Key::Error("Can't calculate size for signature DER encoding. " + Utils::OPENSSLError());

            unsigned char* ptr = nullptr;
            i2d_ECDSA_SIG(sig.get(), &ptr);
            if (ptr == nullptr)
                throw Key::Error("Can't convert signature to DER encoding. " + Utils::OPENSSLError());

            auto res = Base64URL::Block::fromRaw(ptr, sigSize);

            OPENSSL_free(ptr);

            return res;
        }
        static size_t primeSize(const Utils::EVPKeyPtr& key)
        {
            // Field prime size in bytes
            auto ecKey = EVP_PKEY_get1_EC_KEY(key.get());
            if (ecKey == nullptr)
                throw Key::Error("Key is not an Elliptic Curve key.");
            auto degree = (EC_GROUP_get_degree(EC_KEY_get0_group(ecKey)) + 7) / 8;
            EC_KEY_free(ecKey); // EVP_PKEY_get1_EC_KEY increments refcounter of the key
            return degree;
        }
};

}
}
