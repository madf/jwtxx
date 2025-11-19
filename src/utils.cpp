#include "utils.h"

#include "jwtxx/jwt.h" // Key::Error

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/opensslv.h> // OPENSSL_VERSION_NUMBER
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h> // OSSL_PKEY_PARAM_GROUP_NAME
#endif

#include <array>
#include <vector>
#include <functional> // std::function
#include <algorithm> // std::min
#include <utility> // std::move
#include <exception>

#include <cstring> // strerror
#include <cstdio> // fopen, fclose
#include <cerrno> // errno

namespace Utils = JWTXX::Utils;

namespace
{

struct PasswordCallbackTester
{
    explicit PasswordCallbackTester(JWTXX::Key::PasswordCallback cb) noexcept : callback(std::move(cb)) {}
    JWTXX::Key::PasswordCallback callback;
    std::exception_ptr exception;
};

struct FileCloser
{
    void operator()(FILE* fp) const noexcept { fclose(fp); }
};
using FilePtr = std::unique_ptr<FILE, FileCloser>;

struct X509Deleter
{
    void operator()(X509* cert) const noexcept { X509_free(cert); }
};
using X509Ptr = std::unique_ptr<X509, X509Deleter>;

std::string sysError() noexcept
{
    return strerror(errno);
}

Utils::EVPKeyPtr readPublicKey(const std::string& src)
{
    // src is file name
    const FilePtr fp(fopen(src.c_str(), "rbe"));
    if (fp)
        return Utils::EVPKeyPtr(PEM_read_PUBKEY(fp.get(), nullptr, nullptr, nullptr));

    // src is key data
#ifdef CONST_BIO_NEW_MEM_BUF
    // Starting from the OpenSSL 1.0.2 the first parameter of the BIO_new_mem_buf is constant.
    BIO* bio = BIO_new_mem_buf(src.data(), static_cast<int>(src.size()));
#else
    // Before the OpenSSL 1.0.2 the first parameter of the BIO_new_mem_buf is not constant.
    BIO* bio = BIO_new_mem_buf(const_cast<char*>(src.data()), static_cast<int>(src.size()));
#endif
    Utils::EVPKeyPtr key(PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr));

    BIO_free(bio);

    return key;
}

Utils::EVPKeyPtr readCert(const std::string& fileName)
{
    const FilePtr fp(fopen(fileName.c_str(), "rbe"));
    if (!fp)
        throw JWTXX::Key::Error("Can't open key file '" + fileName + "'. " + sysError());
    const X509Ptr cert(PEM_read_X509(fp.get(), nullptr, nullptr, nullptr));
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

Utils::EVPKeyPtr Utils::readPEMPrivateKey(const std::string& fileName, const JWTXX::Key::PasswordCallback& cb, const char* type)
{
    const FilePtr fp(fopen(fileName.c_str(), "rbe"));
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
        if (EVP_PKEY_is_a(key.get(), type) == 0)
            throw Key::Error("Expected " + std::string(type) + " key, got " + std::string(EVP_PKEY_get0_type_name(key.get())));
        return key;
    }
    catch (const PasswordCallbackError&)
    {
        throw Key::Error("Can't read password-protected private key '" + fileName + "' without a password callback function.");
    }
}

Utils::EVPKeyPtr Utils::readPEMPublicKey(const std::string& fileName, const char* type)
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
    if (EVP_PKEY_is_a(key.get(), type) == 0)
        throw Key::Error("Expected " + std::string(type) + " key, got " + std::string(EVP_PKEY_get0_type_name(key.get())));
    return key;
}

std::string Utils::OPENSSLError() noexcept
{
    std::array<char, 256> buf{};
    ERR_error_string_n(ERR_get_error(), buf.data(), buf.size());
    return buf.data();
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

Utils::ECGroupPtr Utils::getECGroup(const EVPKeyPtr& keyPtr)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    size_t groupNameSize = 0;
    EVP_PKEY_get_utf8_string_param(keyPtr.get(), OSSL_PKEY_PARAM_GROUP_NAME, nullptr, 0, &groupNameSize);
    std::vector<char> groupName(groupNameSize + 1);
    if (EVP_PKEY_get_utf8_string_param(keyPtr.get(), OSSL_PKEY_PARAM_GROUP_NAME, groupName.data(), groupName.size(),
                                       &groupNameSize) == 0)
        return nullptr;

    auto nid = OBJ_sn2nid(groupName.data());
    if (nid == NID_undef)
        return nullptr;

    return ECGroupPtr{EC_GROUP_new_by_curve_name(nid)};
#else
    auto ecKey = EVP_PKEY_get1_EC_KEY(keyPtr.get());
    if (ecKey == nullptr)
        return nullptr;

    ECGroupPtr res{EC_GROUP_dup(EC_KEY_get0_group(ecKey))};
    EC_KEY_free(ecKey); // EVP_PKEY_get1_EC_KEY increments refcounter of the key
    return res;
#endif
}
