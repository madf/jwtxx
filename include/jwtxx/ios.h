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
inline
std::ostream& operator<<(std::ostream& stream, const Algorithm& alg)
{
    stream << algToString(alg);
    return stream;
}

/** @fn std::ostream& operator<<(std::ostream& stream, const Value& v)
 *  @brief Outputs a Value to a stream.
 *  @param stream the output stream;
 *  @param v the Value to output.
 *  @return reference to the stream for chaining.
 */
inline
std::ostream& operator<<(std::ostream& stream, const Value& v)
{
    stream << v.toString();
    return stream;
}

}
