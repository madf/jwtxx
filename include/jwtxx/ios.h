#pragma once

/** @file ios.h
 *  @brief Stream input/output functions.
 */

#include "jwt.h"

#include <ostream>

namespace JWTXX
{

/** @fn std::ostream& operator<<(std::ostream& stream, const Algorithm& alg)
 *  @brief Puts algorithm name to a stream.
 *  @param stream the stream;
 *  @param alg the algorithm.
 */
std::ostream& operator<<(std::ostream& stream, const Algorithm& alg)
{
    stream << algToString(alg);
    return stream;
}

}
