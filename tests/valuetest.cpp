#include "jwtxx/value.h"

#define BOOST_TEST_MODULE JWTValueTest

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_CASE(Construction)
{
    auto v = JWTXX::Value::null();
    BOOST_CHECK(v.is<JWTXX::Null>());
    BOOST_CHECK(!v.is<JWTXX::Object>());
    BOOST_CHECK(!v.is<JWTXX::Array>());
    BOOST_CHECK(!v.is<std::string>());
    BOOST_CHECK(!v.is<int64_t>());
    BOOST_CHECK(!v.is<double>());
    BOOST_CHECK(!v.is<bool>());

    BOOST_CHECK_EQUAL(v.toString(), "none");
}
