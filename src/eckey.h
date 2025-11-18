#pragma once

#include "asymmetric.h"
#include "utils.h"

#include <openssl/ecdsa.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L
inline
void ECDSA_SIG_get0(const ECDSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps)
{
   if (pr != NULL)
       *pr = sig->r;
   if (ps != NULL)
       *ps = sig->s;
}

inline
int ECDSA_SIG_set0(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s)
{
   if (r == NULL || s == NULL)
       return 0;
   BN_clear_free(sig->r);
   BN_clear_free(sig->s);
   sig->r = r;
   sig->s = s;
   return 1;
}
#endif

namespace JWTXX
{
namespace Keys
{

class EC : public Key::Impl
{
    public:
        EC(const EVP_MD* digest, const std::string& keyData, const Key::PasswordCallback& cb) noexcept
            : m_key(Asymmetric::Type::EC, digest, keyData, cb), m_primeSize(0)
        {
        }

        std::string sign(const void* data, size_t size) override
        {
            if (m_primeSize == 0)
                m_primeSize = primeSize(m_key.getPrivKey());
            return Base64URL::encode(unpack(m_key.sign(data, size)));
        }

        bool verify(const void* data, size_t size, const std::string& signature) override
        {
            if (m_primeSize == 0)
                m_primeSize = primeSize(m_key.getPubKey());
            return m_key.verify(data, size, pack(Base64URL::decode(signature)));
        }
    private:
        Asymmetric m_key;
        size_t m_primeSize;

        struct SigDeleter
        {
            void operator()(ECDSA_SIG* ptr) { ECDSA_SIG_free(ptr); }
        };
        using SigPtr = std::unique_ptr<ECDSA_SIG, SigDeleter>;
        Base64URL::Block unpack(Base64URL::Block src)
        {
            // Unpack data
            auto srcSig = src.data<const unsigned char*>();
            SigPtr sig(d2i_ECDSA_SIG(nullptr, &srcSig, src.size()));
            if (sig == nullptr)
                throw Key::Error("Can't unpack DER-encoded signature. " + Utils::OPENSSLError());

            const BIGNUM* r = nullptr;
            const BIGNUM* s = nullptr;
            ECDSA_SIG_get0(sig.get(), &r, &s);
            if (r == nullptr || s == nullptr)
                throw Key::Error("Can't unpack DER-encoded signature.");

            // Check sizes
            auto rSize = static_cast<size_t>(BN_num_bytes(r));
            auto sSize = static_cast<size_t>(BN_num_bytes(s));
            if (rSize > m_primeSize || sSize > m_primeSize)
                throw Key::Error("Signature param sizes are inconsistent with the field prime size (p: " + std::to_string(m_primeSize) + ", r: " + std::to_string(rSize) + ", s: " + std::to_string(sSize) + ").");

            // Put them raw, leading zeros
            auto dest = Base64URL::Block::zero(m_primeSize * 2);
            BN_bn2bin(r, dest.dataAt<unsigned char*>(m_primeSize - rSize));
            BN_bn2bin(s, dest.dataAt<unsigned char*>(m_primeSize * 2 - sSize));
            return dest;
        }
        Base64URL::Block pack(Base64URL::Block src)
        {
            // Broken signature here is a validation error
            if (src.size() != m_primeSize * 2)
                throw JWT::ValidationError("Signature size is inconsistent with the field prime size (p: " + std::to_string(m_primeSize) + ", 2p: " + std::to_string(m_primeSize * 2) + ", s: " + std::to_string(src.size()) + ").");

            auto r = BN_bin2bn(src.data<const unsigned char*>(), m_primeSize, nullptr);
            auto s = BN_bin2bn(src.dataAt<const unsigned char*>(m_primeSize), m_primeSize, nullptr);

            SigPtr sig(ECDSA_SIG_new());
            ECDSA_SIG_set0(sig.get(), r, s);

            unsigned char* ptr = nullptr;
            auto sigSize = i2d_ECDSA_SIG(sig.get(), &ptr);
            if (ptr == nullptr || sigSize <= 0)
                throw Key::Error("Can't convert signature to DER encoding. " + Utils::OPENSSLError());

            auto res = Base64URL::Block::fromRaw(ptr, sigSize);

            OPENSSL_free(ptr);

            return res;
        }
        static size_t primeSize(const Utils::EVPKeyPtr& key)
        {
            // Field prime size in bytes
            return (EC_GROUP_get_degree(getECGroup(key).get()) + 7) / 8;
        }
};

}
}
