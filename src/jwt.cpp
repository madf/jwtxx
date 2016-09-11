#include "jwtxx/jwt.h"

#include "utils.h"

using JWTXX::Algorithm;
using JWTXX::Key;
using JWTXX::JWT;

namespace
{

struct NoneKey : public Key::Impl
{
}

Key* createKey(Algorithm alg, const std::string& keyData)
{
    switch (alg)
    {
        case none: return new Keys::None;
    }
}

}

Key::Key(Algorithm alg, const std::string& keyData)
    : m_impl(createKey(alg, keyData))
{
}

std::string Key::sign(const void* data, size_t size) const
{
    return m_impl->sign(data, size);
}

bool Key::verify(const void* data, size_t size, const std::string& signature) const
{
    return m_impl->verify(data, size, signature);
}
