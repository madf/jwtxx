#pragma once

#include "jwtxx/jwt.h"

struct InitOpenSSL
{
    InitOpenSSL(){ JWTXX::enableOpenSSLErrors(); }
};
