#pragma once

#include "jwtxx/value.h"

#include <string>

namespace JWTXX
{

std::string toJSON(const Value::Object& data) noexcept;
Value::Object fromJSON(const std::string& data);

}
