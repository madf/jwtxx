#include "json.h"

using JWTXX::JWT;

std::string JWTXX::toJSON(const JWT::Pairs& data)
{
    std::string res;
    for (const auto& item : data)
    {
        if (!res.empty())
            res += ",";
        res += "\"" + item.first + "\":\"" + item.second + "\"";
    }
    return "{" + res + "}";
}
