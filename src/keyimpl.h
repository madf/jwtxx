#pragma once

#include "jwtxx/jwt.h"

#include <string>

namespace JWTXX
{

struct Key::Impl
{
    virtual std::string sign(const void* data, size_t size) const = 0;
    virtual bool verify(const void* data, size_t size, const std::string& signature) const = 0;
};

}
