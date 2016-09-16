#pragma once

#include <memory>

#include <cstdio> // fopen, fclose

#include <openssl/evp.h>
#include <openssl/ec.h>

namespace JWTXX
{
namespace Utils
{

struct FileCloser
{
    void operator()(FILE* fp) { fclose(fp); }
};
typedef std::unique_ptr<FILE, FileCloser> FilePtr;

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

EVPKeyPtr readPEMPrivateKey(const std::string& fileName);
EVPKeyPtr readPEMPublicKey(const std::string& fileName);

std::string OPENSSLError();

}
}
