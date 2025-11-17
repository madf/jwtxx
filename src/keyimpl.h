#pragma once

#include "jwtxx/jwt.h"

#include <string>

namespace JWTXX
{

struct Key::Impl
{
    // Need this for polymorphic behavior.
    virtual ~Impl() = default;
    // Need this due to the Rule of Five.
    Impl() = default;
    Impl(const Impl&) = delete;
    Impl& operator=(const Impl&) = delete;
    Impl(Impl&&) = default;
    Impl& operator=(Impl&&) = default;

    virtual std::string sign(const void* data, size_t size) = 0;
    virtual bool verify(const void* data, size_t size, const std::string& signature) = 0;
};

}
