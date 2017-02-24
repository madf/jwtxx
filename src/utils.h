#pragma once

#include "jwtxx/jwt.h"

#include <memory>
#include <tuple>

#include <openssl/evp.h>
#include <openssl/ec.h>

namespace JWTXX
{
namespace Utils
{

struct EVPKeyDeleter
{
    void operator()(EVP_PKEY* key) { EVP_PKEY_free(key); }
};
typedef std::unique_ptr<EVP_PKEY, EVPKeyDeleter> EVPKeyPtr;

struct EVPMDCTXDeleter
{
    void operator()(EVP_MD_CTX* ctx) { EVP_MD_CTX_destroy(ctx); }
};
typedef std::unique_ptr<EVP_MD_CTX, EVPMDCTXDeleter> EVPMDCTXPtr;

EVPKeyPtr readPEMPrivateKey(const std::string& fileName, Key::PasswordCallback cb);
EVPKeyPtr readPEMPublicKey(const std::string& fileName);

std::string OPENSSLError();

typedef std::tuple<std::string, std::string, std::string> Triple;

Triple split(const std::string& token);

}
}
