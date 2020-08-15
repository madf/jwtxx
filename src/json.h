#pragma once

#include "jwtxx/jwt.h"

#include <string>

namespace JWTXX
{

std::string toJSON(const Pairs& data) noexcept;
Pairs fromJSON(const std::string& data);

}
