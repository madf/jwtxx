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
    void operator()(EVP_PKEY* keyp) { EVP_PKEY_free(keyp); }
};
typedef std::unique_ptr<EVP_PKEY, EVPKeyDeleter> EVPKeyPtr;

struct ECKeyDeleter
{
    void operator()(EC_KEY* keyp) { EC_KEY_free(keyp); }
};
typedef std::unique_ptr<EC_KEY, ECKeyDeleter> ECKeyPtr;

struct EVPMDCTXDeleter
{
    void operator()(EVP_MD_CTX* ctx) { EVP_MD_CTX_destroy(ctx); }
};
typedef std::unique_ptr<EVP_MD_CTX, EVPMDCTXDeleter> EVPMDCTXPtr;

EVPKeyPtr readPEMPrivateKey(const std::string& fileName);
EVPKeyPtr readPEMPublicKey(const std::string& fileName);
ECKeyPtr readECPrivateKey(const std::string& fileName);
ECKeyPtr readECPublicKey(const std::string& fileName);

std::string OPENSSLError();

}
}
