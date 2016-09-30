#pragma once

#include "jwtxx/jwt.h"

namespace JWTXX
{

std::string toJSON(const Pairs& data);
Pairs fromJSON(const std::string& data);

}
