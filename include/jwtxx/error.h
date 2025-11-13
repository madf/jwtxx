#pragma once

#include <stdexcept>

namespace JWTXX
{

/** @class Error
 *  @brief Base class for all exceptions in the library.
 */
struct Error : public std::runtime_error
{
    /** @brief Constructor. */
    explicit Error(const std::string& message) noexcept : runtime_error(message) {}
};

}
