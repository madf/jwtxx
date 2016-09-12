#pragma once

#include "jwt.h"

#include <ostream>

namespace JWTXX
{

std::ostream& operator<<(std::ostream& stream, const Algorithm& alg)
{
    stream << algToString(alg);
    return stream;
}

}
