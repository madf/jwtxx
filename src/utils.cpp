#include "utils.h"

#include "jwtxx/jwt.h" // Key::Error

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/err.h>

#include <algorithm> // std::min
#include <exception>

#include <cstring> // strerror
#include <cstdio> // fopen, fclose
#include <cerrno> // errno

namespace Utils = JWTXX::Utils;

namespace
{

struct PasswordCallbackTester
{
    explicit PasswordCallbackTester(const JWTXX::Key::PasswordCallback& cb) noexcept : callback(cb) {}
    JWTXX::Key::PasswordCallback callback;
    std::exception_ptr exception;
};

struct FileCloser
{
    void operator()(FILE* fp) const noexcept { fclose(fp); }
};
typedef std::unique_ptr<FILE, FileCloser> FilePtr;

struct X509Deleter
{
    void operator()(X509* cert) const noexcept { X509_free(cert); }
};
typedef std::unique_ptr<X509, X509Deleter> X509Ptr;

std::string sysError() noexcept
{
    return strerror(errno);
}

Utils::EVPKeyPtr readPublicKey(const std::string& src)
{
    // src is key data
    if (src.find("-----BEGIN") == 0)
    {
        BIO* bio = BIO_new_mem_buf(src.data(), static_cast<int>(src.size()));
        Utils::EVPKeyPtr key(PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr));

        BIO_free(bio);

        return key;
    }

    // src is file name
    FilePtr fp(fopen(src.c_str(), "rb"));
    if (!fp)
        throw JWTXX::Key::Error("Can't open key file '" + src + "'. " + sysError());

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

int passwordCallback(char* buf, int size, int /*rwflag*/, void* data)
{
    if (data == nullptr)
        return 0;
    PasswordCallbackTester& tester = *static_cast<PasswordCallbackTester*>(data);
    try
    {
        auto password = tester.callback();
        std::strncpy(buf, password.c_str(), size - 1);
        buf[size - 1] = '\0';
        return std::min<int>(size, password.length());
    }
    catch (...)
    {
        tester.exception = std::current_exception();
        return 0;
    }
}

}

Utils::EVPKeyPtr Utils::readPEMPrivateKey(const std::string& fileName, const JWTXX::Key::PasswordCallback& cb)
{
    FilePtr fp(fopen(fileName.c_str(), "rb"));
    if (!fp)
        throw Key::Error("Can't open key file '" + fileName + "'. " + sysError());
    try
    {
        PasswordCallbackTester tester(cb);
        EVPKeyPtr key(PEM_read_PrivateKey(fp.get(), nullptr, passwordCallback, &tester));
        if (tester.exception)
            std::rethrow_exception(tester.exception);
        if (!key)
            throw Key::Error("Can't read private key '" + fileName + "'. " + OPENSSLError());
        return key;
    }
    catch (const PasswordCallbackError&)
    {
        throw Key::Error("Can't read password-protected private key '" + fileName + "' without a password callback function.");
    }
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

std::string Utils::OPENSSLError() noexcept
{
    char buf[256];
    ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
    return buf;
}

Utils::Triple Utils::split(const std::string& token)
{
    auto pos = token.find_first_of('.');
    if (pos == std::string::npos)
        throw JWT::ParseError("JWT should have at least 2 parts separated by a dot.");
    auto spos = token.find_first_of('.', pos + 1);
    if (spos == std::string::npos)
        return std::make_tuple(token.substr(0, pos),
                               token.substr(pos + 1, token.length() - pos - 1),
                               "");
    return std::make_tuple(token.substr(0, pos),
                           token.substr(pos + 1, spos - pos - 1),
                           token.substr(spos + 1, token.length() - spos - 1));
}
