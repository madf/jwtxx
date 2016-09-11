#include "utils.h"

#include "jwtxx/jwt.h" // Key::Error

using namespace JWTXX;

EVPKeyPtr Utils::readPEMPrivateKey(const std::string& fileName)
{
    FilePtr fp(fopen(m_data.c_str(), "rb"));
    if (!fp)
        throw Key::Error("Can't open key file '" + m_data + "'. " + sysError());
    EVPKeyPtr key(PEM_read_Private(fp, nullptr, nullptr, nullptr));
    if (!key)
        throw Key::Error("Can't read public key '" + m_data + "'. " + OPENSSLError());
    return key;
}

EVPKeyPtr Utils::readPEMPublicKey(const std::string& fileName)
{
    FilePtr fp(fopen(m_data.c_str(), "rb"));
    if (!fp)
        throw Key::Error("Can't open key file '" + m_data + "'. " + sysError());
    EVPKeyPtr key(PEM_read_PUBKEY(fp, nullptr, nullptr, nullptr));
    if (!key)
        throw Key::Error("Can't read public key '" + m_data + "'. " + OPENSSLError());
    return key;
}

ECKeyPtr Utils::readECPrivateKey(const std::string& fileName)
{
    auto pem = readPEMPrivateKey(fileName);
    ECKeyPtr key(EVP_PKEY_get1_EC_KEY(pem.get()));
    if (!key)
        throw Key::Error("Private key '" + fileName + "' is not an Elliptic Curve key.");
    return key;
}

ECKeyPtr Utils::readECPublicKey(const std::string& fileName)
{
    auto pem = readPEMPublicKey(fileName);
    ECKeyPtr key(EVP_PKEY_get1_EC_KEY(pem.get()));
    if (!key)
        throw Key::Error("Public key '" + fileName + "' is not an Elliptic Curve key.");
    return key;
}
