#include "utils.h"

#include "jwtxx/jwt.h" // Key::Error

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/err.h>

#include <cstring> // strerror
#include <cerrno> // errno

namespace Utils = JWTXX::Utils;

namespace
{

struct FileCloser
{
    void operator()(FILE* fp) { fclose(fp); }
};
typedef std::unique_ptr<FILE, FileCloser> FilePtr;

struct X509Deleter
{
    void operator()(X509* cert) { X509_free(cert); }
};
typedef std::unique_ptr<X509, X509Deleter> X509Ptr;

std::string sysError()
{
    return strerror(errno);
}

Utils::EVPKeyPtr readPublicKey(const std::string& fileName)
{
    FilePtr fp(fopen(fileName.c_str(), "rb"));
    if (!fp)
        throw JWTXX::Key::Error("Can't open key file '" + fileName + "'. " + sysError());
    return Utils::EVPKeyPtr(PEM_read_PUBKEY(fp.get(), nullptr, nullptr, nullptr));
}

Utils::EVPKeyPtr readCert(const std::string& fileName)
{
    FilePtr fp(fopen(fileName.c_str(), "rb"));
    if (!fp)
        throw JWTXX::Key::Error("Can't open key file '" + fileName + "'. " + sysError());
    X509Ptr cert(PEM_read_X509(fp.get(), nullptr, nullptr, nullptr));
    if (!cert)
        return {};
    return Utils::EVPKeyPtr(X509_get_pubkey(cert.get()));
}

}

Utils::EVPKeyPtr Utils::readPEMPrivateKey(const std::string& fileName)
{
    FilePtr fp(fopen(fileName.c_str(), "rb"));
    if (!fp)
        throw Key::Error("Can't open key file '" + fileName + "'. " + sysError());
    EVPKeyPtr key(PEM_read_PrivateKey(fp.get(), nullptr, nullptr, nullptr));
    if (!key)
        throw Key::Error("Can't read private key '" + fileName + "'. " + OPENSSLError());
    return key;
}

Utils::EVPKeyPtr Utils::readPEMPublicKey(const std::string& fileName)
{
    auto key = readPublicKey(fileName);
    std::string pkError;
    if (!key)
    {
        pkError = OPENSSLError();
        key = readCert(fileName);
    }
    if (!key)
        throw Key::Error("File '" + fileName + "' is neither public key (" + pkError + ") nor certificate (" + OPENSSLError() + ").");
    return key;
}

std::string Utils::OPENSSLError()
{
    char buf[256];
    ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
    return buf;
}
