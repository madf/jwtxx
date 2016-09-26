#include "jwtxx/jwt.h"
#include "jwtxx/ios.h"

#include "initopenssl.h"

#define BOOST_TEST_MODULE JWTRSAAlgTest

#include <boost/test/included/unit_test.hpp>

BOOST_GLOBAL_FIXTURE(InitOpenSSL)

BOOST_AUTO_TEST_CASE(TestCtor256)
{
    JWTXX::JWT jwt(JWTXX::Algorithm::RS256, {{"iss", "madf"}});

    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::RS256);
    BOOST_CHECK(!jwt.claims().empty());
    BOOST_CHECK(!jwt.header().empty());
    auto header = jwt.header();
    BOOST_CHECK_EQUAL(header["alg"], "RS256");
    BOOST_CHECK_EQUAL(header["typ"], "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss"), "madf");
    auto token = jwt.token("rsa-2048-key-pair.pem");
    // Jansson uses hashtables form JSON objects and hash function implementation reads over the boundary of the string, yet word-aligned, so actual order of header fields and claims is undefined.
    BOOST_CHECK(token == "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIn0.GpuCt3HLj3ToT8SYa-EErTgd4deISPXrAq7c_fwt3837wMtFripY1DOhEH-YLxexhFwjkHrlNRWNV7jlamS32zw4y7_lF9zlQ4AgdGOXsNPUGjPXXuCPvVr84sBGpIjki9LUFa-qTGAe1qNsCH7rwG-LF4c0BOF2tnhwXSaipgFcInoHIhoj9KQBT7kkTfmXiBTp8ITkWnWMtmVaIHay6Z3aiOu-jRDWPlzoIWwLVfAPL9ti8uKzMmUGGhpiwPgwZnIoPVgyjM6U0ahHr_tEeeBYCa-7J8gYPEpXK1TkOQq1uUpk52LbrsieZMpsSTbbybGwBmBl2FBC3tjjCc8tug" || token == "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJtYWRmIn0.gO-HSMMeWKCmB3xFo7pvFWVNxpo17mWTKv9H2giWXJUQhzNOc2PSxhElrz7swGmpo9m7NShGueF-SlRDBgq8olgX_NDOvzvXSlVusZg8COU_PkxEd_NolEIlAoIGXGwFfpVUiv5VY_kV2vvONns1Sifr5cJ1wIbtONhpI4B0GntvBoQCq9XgbmgRN_0pOEuMs9p4xw1FXdWXv1wgrgceHJ-1QTCRXAhA9TRAxn_MNvb2Y5ftj4j_f6FsXA4xrurNOolcNgS9Fi8xhQEJVe3nwF_RIfSdHE3F5EPDvxYX6-ce-C6Acg1acwad8LEEaYpIOIgYvyJa3nmh_2hxuEGm8g");
}

BOOST_AUTO_TEST_CASE(TestCtor384)
{
    JWTXX::JWT jwt(JWTXX::Algorithm::RS384, {{"iss", "madf"}});

    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::RS384);
    BOOST_CHECK(!jwt.claims().empty());
    BOOST_CHECK(!jwt.header().empty());
    auto header = jwt.header();
    BOOST_CHECK_EQUAL(header["alg"], "RS384");
    BOOST_CHECK_EQUAL(header["typ"], "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss"), "madf");
    auto token = jwt.token("rsa-2048-key-pair.pem");
    // Jansson uses hashtables form JSON objects and hash function implementation reads over the boundary of the string, yet word-aligned, so actual order of header fields and claims is undefined.
    BOOST_CHECK(token == "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIn0.s8DCHwP41dmCmeXSs6cUJRAFtQqOfTtk1S54MlH06By98ybpWzhY_lAwEAI4-QAIRoPvkZPtF03Qn1ZX1pETfDKk96zPTm8mojjpBfuO-LZgiQDcStf5hByhV4YBKYY5kNfuCuGBOdtPer7Uv-41aVyoIkGhNW-YwtHM3noBaWTP6igZHztKlQs816vEFQlNp_sA5yQk7qhlhHkAAFec1Db1apQke3MGn7m1wKh16CU4lscLDFze6S80WuXwBot1ksthvutYYTeRnIHeLz3ty9pGtaVBGW8EbcaDj2biBhVHRTiOS1oeZ-O8h2Nn9sDaV5_S2OHf3BTgLOZNbih5uQ" || token == "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzM4NCJ9.eyJpc3MiOiJtYWRmIn0.tU5SWVRjc2BgVdZN4heYolUFhDIc9dHOxw7zYFstZKwEbj_K_9IRsl2kJ9Nw4NXGBntkBMIp6U1cqW9xkgiH1u4IAalL0q0NBIOW5-JEqUO65iDaDLkObJY65tbDT2q-CpsCBlYpULcWaZWj-3Xjn3Z0oTItjn40c4BJ8Ra0MaKDRKZNMScMnV7mHKylsPe-0aiRWK5QMaW_4KUjKmcJHpqY0aCA1yov1RLauPhXFC3w4KU_BbLJN25fMkSNwapmPKC2NQxuGjQRglAlq-XbxMe1FKieLPGCAPJLkzm9BHkZ0mmm405jVCfxEAw5DOVRrP5xo_2mpOxjIbBXJFPWMg");
}

BOOST_AUTO_TEST_CASE(TestCtor512)
{
    JWTXX::JWT jwt(JWTXX::Algorithm::RS512, {{"iss", "madf"}});

    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::RS512);
    BOOST_CHECK(!jwt.claims().empty());
    BOOST_CHECK(!jwt.header().empty());
    auto header = jwt.header();
    BOOST_CHECK_EQUAL(header["alg"], "RS512");
    BOOST_CHECK_EQUAL(header["typ"], "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss"), "madf");
    auto token = jwt.token("rsa-2048-key-pair.pem");
    // Jansson uses hashtables form JSON objects and hash function implementation reads over the boundary of the string, yet word-aligned, so actual order of header fields and claims is undefined.
    BOOST_CHECK(token == "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzUxMiJ9.eyJpc3MiOiJtYWRmIn0.G8vv-IyeoIg5SWcN1Qb3-9kLPr8tnUSbBPO32Srvce04Lfe0sEWmlbBD5FR7dTYtpd2iMLwu7ytFsb0n_pOD1_ti_XAytQvJH6w6pL0saABs8y_Gj1AWONfIqGGw-2ChgItUsGpHt3yr7i4gV6bKYtU2KFcwFQ3c7bXpLjV9paptLQNwOHTjadmNcuexV443pz1NlaOP9DUjTzO2WNaiAokNtJ4wh6Emdjors844p4bCnah0o4STUYbcvRILYMVIpxrew7lcrLiA-vF8kD-Pxeb_Gna8sTIQ3gx7K1fL10Mg0wPEake4Qko29gy8AXx1qki5hEYx9Pe8CxezBfyFmA" || token == "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIn0.fyDpJVopst2qpHzs63NRWZ9zY04KrxfQmiF0zt3i-ACB38hnBo90r_PlrhMiMU8HU52_JxcBUAi5lSQHakX16EQyR0pEwZZfoCbeI0lOzpt0yrXAYyGvJC8WlE1Mm9Ehd8iUgcvvc9nL0_gRT-4RSU7kVOHOlwIRiN6fE28si22Jjtb5hf0KjebLj7BTeNnVB17SK9qMMn7VuYtRKj767FDpnZuOwNkDvb2qeL3IzbJnTYgpOVMoinHWAvR_innn9BjzCOEkFqgj6KKzQiEbVI6tbHfD-qOHHVDF1a0eERtCUuu92LesUyWJj3etgnmmNFI5EVjDtQkldQuuFgARUw");
}

BOOST_AUTO_TEST_CASE(TestParser256)
{
    JWTXX::JWT jwt("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIn0.GpuCt3HLj3ToT8SYa-EErTgd4deISPXrAq7c_fwt3837wMtFripY1DOhEH-YLxexhFwjkHrlNRWNV7jlamS32zw4y7_lF9zlQ4AgdGOXsNPUGjPXXuCPvVr84sBGpIjki9LUFa-qTGAe1qNsCH7rwG-LF4c0BOF2tnhwXSaipgFcInoHIhoj9KQBT7kkTfmXiBTp8ITkWnWMtmVaIHay6Z3aiOu-jRDWPlzoIWwLVfAPL9ti8uKzMmUGGhpiwPgwZnIoPVgyjM6U0ahHr_tEeeBYCa-7J8gYPEpXK1TkOQq1uUpk52LbrsieZMpsSTbbybGwBmBl2FBC3tjjCc8tug", JWTXX::Key(JWTXX::Algorithm::RS256, "public-rsa-2048-key.pem"));

    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::RS256);
    BOOST_CHECK(!jwt.claims().empty());
    BOOST_CHECK(!jwt.header().empty());
    auto header = jwt.header();
    BOOST_CHECK_EQUAL(header["alg"], "RS256");
    BOOST_CHECK_EQUAL(header["typ"], "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss"), "madf");
    auto token = jwt.token("rsa-2048-key-pair.pem");
    // Jansson uses hashtables form JSON objects and hash function implementation reads over the boundary of the string, yet word-aligned, so actual order of header fields and claims is undefined.
    BOOST_CHECK(token == "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIn0.GpuCt3HLj3ToT8SYa-EErTgd4deISPXrAq7c_fwt3837wMtFripY1DOhEH-YLxexhFwjkHrlNRWNV7jlamS32zw4y7_lF9zlQ4AgdGOXsNPUGjPXXuCPvVr84sBGpIjki9LUFa-qTGAe1qNsCH7rwG-LF4c0BOF2tnhwXSaipgFcInoHIhoj9KQBT7kkTfmXiBTp8ITkWnWMtmVaIHay6Z3aiOu-jRDWPlzoIWwLVfAPL9ti8uKzMmUGGhpiwPgwZnIoPVgyjM6U0ahHr_tEeeBYCa-7J8gYPEpXK1TkOQq1uUpk52LbrsieZMpsSTbbybGwBmBl2FBC3tjjCc8tug" || token == "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJtYWRmIn0.gO-HSMMeWKCmB3xFo7pvFWVNxpo17mWTKv9H2giWXJUQhzNOc2PSxhElrz7swGmpo9m7NShGueF-SlRDBgq8olgX_NDOvzvXSlVusZg8COU_PkxEd_NolEIlAoIGXGwFfpVUiv5VY_kV2vvONns1Sifr5cJ1wIbtONhpI4B0GntvBoQCq9XgbmgRN_0pOEuMs9p4xw1FXdWXv1wgrgceHJ-1QTCRXAhA9TRAxn_MNvb2Y5ftj4j_f6FsXA4xrurNOolcNgS9Fi8xhQEJVe3nwF_RIfSdHE3F5EPDvxYX6-ce-C6Acg1acwad8LEEaYpIOIgYvyJa3nmh_2hxuEGm8g");
}

BOOST_AUTO_TEST_CASE(TestParserDifferentFieldOrder256)
{
    JWTXX::JWT jwt("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJtYWRmIn0.gO-HSMMeWKCmB3xFo7pvFWVNxpo17mWTKv9H2giWXJUQhzNOc2PSxhElrz7swGmpo9m7NShGueF-SlRDBgq8olgX_NDOvzvXSlVusZg8COU_PkxEd_NolEIlAoIGXGwFfpVUiv5VY_kV2vvONns1Sifr5cJ1wIbtONhpI4B0GntvBoQCq9XgbmgRN_0pOEuMs9p4xw1FXdWXv1wgrgceHJ-1QTCRXAhA9TRAxn_MNvb2Y5ftj4j_f6FsXA4xrurNOolcNgS9Fi8xhQEJVe3nwF_RIfSdHE3F5EPDvxYX6-ce-C6Acg1acwad8LEEaYpIOIgYvyJa3nmh_2hxuEGm8g" , JWTXX::Key(JWTXX::Algorithm::RS256, "public-rsa-2048-key.pem"));

    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::RS256);
    BOOST_CHECK(!jwt.claims().empty());
    BOOST_CHECK(!jwt.header().empty());
    auto header = jwt.header();
    BOOST_CHECK_EQUAL(header["alg"], "RS256");
    BOOST_CHECK_EQUAL(header["typ"], "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss"), "madf");
    auto token = jwt.token("rsa-2048-key-pair.pem");
    // Jansson uses hashtables form JSON objects and hash function implementation reads over the boundary of the string, yet word-aligned, so actual order of header fields and claims is undefined.
    BOOST_CHECK(token == "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIn0.GpuCt3HLj3ToT8SYa-EErTgd4deISPXrAq7c_fwt3837wMtFripY1DOhEH-YLxexhFwjkHrlNRWNV7jlamS32zw4y7_lF9zlQ4AgdGOXsNPUGjPXXuCPvVr84sBGpIjki9LUFa-qTGAe1qNsCH7rwG-LF4c0BOF2tnhwXSaipgFcInoHIhoj9KQBT7kkTfmXiBTp8ITkWnWMtmVaIHay6Z3aiOu-jRDWPlzoIWwLVfAPL9ti8uKzMmUGGhpiwPgwZnIoPVgyjM6U0ahHr_tEeeBYCa-7J8gYPEpXK1TkOQq1uUpk52LbrsieZMpsSTbbybGwBmBl2FBC3tjjCc8tug" || token == "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJtYWRmIn0.gO-HSMMeWKCmB3xFo7pvFWVNxpo17mWTKv9H2giWXJUQhzNOc2PSxhElrz7swGmpo9m7NShGueF-SlRDBgq8olgX_NDOvzvXSlVusZg8COU_PkxEd_NolEIlAoIGXGwFfpVUiv5VY_kV2vvONns1Sifr5cJ1wIbtONhpI4B0GntvBoQCq9XgbmgRN_0pOEuMs9p4xw1FXdWXv1wgrgceHJ-1QTCRXAhA9TRAxn_MNvb2Y5ftj4j_f6FsXA4xrurNOolcNgS9Fi8xhQEJVe3nwF_RIfSdHE3F5EPDvxYX6-ce-C6Acg1acwad8LEEaYpIOIgYvyJa3nmh_2hxuEGm8g");
}

BOOST_AUTO_TEST_CASE(TestParser384)
{
    JWTXX::JWT jwt( "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIn0.s8DCHwP41dmCmeXSs6cUJRAFtQqOfTtk1S54MlH06By98ybpWzhY_lAwEAI4-QAIRoPvkZPtF03Qn1ZX1pETfDKk96zPTm8mojjpBfuO-LZgiQDcStf5hByhV4YBKYY5kNfuCuGBOdtPer7Uv-41aVyoIkGhNW-YwtHM3noBaWTP6igZHztKlQs816vEFQlNp_sA5yQk7qhlhHkAAFec1Db1apQke3MGn7m1wKh16CU4lscLDFze6S80WuXwBot1ksthvutYYTeRnIHeLz3ty9pGtaVBGW8EbcaDj2biBhVHRTiOS1oeZ-O8h2Nn9sDaV5_S2OHf3BTgLOZNbih5uQ", JWTXX::Key(JWTXX::Algorithm::RS384, "public-rsa-2048-key.pem"));

    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::RS384);
    BOOST_CHECK(!jwt.claims().empty());
    BOOST_CHECK(!jwt.header().empty());
    auto header = jwt.header();
    BOOST_CHECK_EQUAL(header["alg"], "RS384");
    BOOST_CHECK_EQUAL(header["typ"], "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss"), "madf");
    auto token = jwt.token("rsa-2048-key-pair.pem");
    // Jansson uses hashtables form JSON objects and hash function implementation reads over the boundary of the string, yet word-aligned, so actual order of header fields and claims is undefined.
    BOOST_CHECK(token == "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIn0.s8DCHwP41dmCmeXSs6cUJRAFtQqOfTtk1S54MlH06By98ybpWzhY_lAwEAI4-QAIRoPvkZPtF03Qn1ZX1pETfDKk96zPTm8mojjpBfuO-LZgiQDcStf5hByhV4YBKYY5kNfuCuGBOdtPer7Uv-41aVyoIkGhNW-YwtHM3noBaWTP6igZHztKlQs816vEFQlNp_sA5yQk7qhlhHkAAFec1Db1apQke3MGn7m1wKh16CU4lscLDFze6S80WuXwBot1ksthvutYYTeRnIHeLz3ty9pGtaVBGW8EbcaDj2biBhVHRTiOS1oeZ-O8h2Nn9sDaV5_S2OHf3BTgLOZNbih5uQ" || token == "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzM4NCJ9.eyJpc3MiOiJtYWRmIn0.tU5SWVRjc2BgVdZN4heYolUFhDIc9dHOxw7zYFstZKwEbj_K_9IRsl2kJ9Nw4NXGBntkBMIp6U1cqW9xkgiH1u4IAalL0q0NBIOW5-JEqUO65iDaDLkObJY65tbDT2q-CpsCBlYpULcWaZWj-3Xjn3Z0oTItjn40c4BJ8Ra0MaKDRKZNMScMnV7mHKylsPe-0aiRWK5QMaW_4KUjKmcJHpqY0aCA1yov1RLauPhXFC3w4KU_BbLJN25fMkSNwapmPKC2NQxuGjQRglAlq-XbxMe1FKieLPGCAPJLkzm9BHkZ0mmm405jVCfxEAw5DOVRrP5xo_2mpOxjIbBXJFPWMg");
}

BOOST_AUTO_TEST_CASE(TestParserDifferentFieldOrder384)
{
    JWTXX::JWT jwt("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzM4NCJ9.eyJpc3MiOiJtYWRmIn0.tU5SWVRjc2BgVdZN4heYolUFhDIc9dHOxw7zYFstZKwEbj_K_9IRsl2kJ9Nw4NXGBntkBMIp6U1cqW9xkgiH1u4IAalL0q0NBIOW5-JEqUO65iDaDLkObJY65tbDT2q-CpsCBlYpULcWaZWj-3Xjn3Z0oTItjn40c4BJ8Ra0MaKDRKZNMScMnV7mHKylsPe-0aiRWK5QMaW_4KUjKmcJHpqY0aCA1yov1RLauPhXFC3w4KU_BbLJN25fMkSNwapmPKC2NQxuGjQRglAlq-XbxMe1FKieLPGCAPJLkzm9BHkZ0mmm405jVCfxEAw5DOVRrP5xo_2mpOxjIbBXJFPWMg", JWTXX::Key(JWTXX::Algorithm::RS384, "public-rsa-2048-key.pem"));

    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::RS384);
    BOOST_CHECK(!jwt.claims().empty());
    BOOST_CHECK(!jwt.header().empty());
    auto header = jwt.header();
    BOOST_CHECK_EQUAL(header["alg"], "RS384");
    BOOST_CHECK_EQUAL(header["typ"], "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss"), "madf");
    auto token = jwt.token("rsa-2048-key-pair.pem");
    // Jansson uses hashtables form JSON objects and hash function implementation reads over the boundary of the string, yet word-aligned, so actual order of header fields and claims is undefined.
    BOOST_CHECK(token == "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIn0.s8DCHwP41dmCmeXSs6cUJRAFtQqOfTtk1S54MlH06By98ybpWzhY_lAwEAI4-QAIRoPvkZPtF03Qn1ZX1pETfDKk96zPTm8mojjpBfuO-LZgiQDcStf5hByhV4YBKYY5kNfuCuGBOdtPer7Uv-41aVyoIkGhNW-YwtHM3noBaWTP6igZHztKlQs816vEFQlNp_sA5yQk7qhlhHkAAFec1Db1apQke3MGn7m1wKh16CU4lscLDFze6S80WuXwBot1ksthvutYYTeRnIHeLz3ty9pGtaVBGW8EbcaDj2biBhVHRTiOS1oeZ-O8h2Nn9sDaV5_S2OHf3BTgLOZNbih5uQ" || token == "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzM4NCJ9.eyJpc3MiOiJtYWRmIn0.tU5SWVRjc2BgVdZN4heYolUFhDIc9dHOxw7zYFstZKwEbj_K_9IRsl2kJ9Nw4NXGBntkBMIp6U1cqW9xkgiH1u4IAalL0q0NBIOW5-JEqUO65iDaDLkObJY65tbDT2q-CpsCBlYpULcWaZWj-3Xjn3Z0oTItjn40c4BJ8Ra0MaKDRKZNMScMnV7mHKylsPe-0aiRWK5QMaW_4KUjKmcJHpqY0aCA1yov1RLauPhXFC3w4KU_BbLJN25fMkSNwapmPKC2NQxuGjQRglAlq-XbxMe1FKieLPGCAPJLkzm9BHkZ0mmm405jVCfxEAw5DOVRrP5xo_2mpOxjIbBXJFPWMg");
}

BOOST_AUTO_TEST_CASE(TestParser512)
{
    JWTXX::JWT jwt( "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzUxMiJ9.eyJpc3MiOiJtYWRmIn0.G8vv-IyeoIg5SWcN1Qb3-9kLPr8tnUSbBPO32Srvce04Lfe0sEWmlbBD5FR7dTYtpd2iMLwu7ytFsb0n_pOD1_ti_XAytQvJH6w6pL0saABs8y_Gj1AWONfIqGGw-2ChgItUsGpHt3yr7i4gV6bKYtU2KFcwFQ3c7bXpLjV9paptLQNwOHTjadmNcuexV443pz1NlaOP9DUjTzO2WNaiAokNtJ4wh6Emdjors844p4bCnah0o4STUYbcvRILYMVIpxrew7lcrLiA-vF8kD-Pxeb_Gna8sTIQ3gx7K1fL10Mg0wPEake4Qko29gy8AXx1qki5hEYx9Pe8CxezBfyFmA", JWTXX::Key(JWTXX::Algorithm::RS512, "public-rsa-2048-key.pem"));

    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::RS512);
    BOOST_CHECK(!jwt.claims().empty());
    BOOST_CHECK(!jwt.header().empty());
    auto header = jwt.header();
    BOOST_CHECK_EQUAL(header["alg"], "RS512");
    BOOST_CHECK_EQUAL(header["typ"], "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss"), "madf");
    auto token = jwt.token("rsa-2048-key-pair.pem");
    // Jansson uses hashtables form JSON objects and hash function implementation reads over the boundary of the string, yet word-aligned, so actual order of header fields and claims is undefined.
    BOOST_CHECK(token == "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzUxMiJ9.eyJpc3MiOiJtYWRmIn0.G8vv-IyeoIg5SWcN1Qb3-9kLPr8tnUSbBPO32Srvce04Lfe0sEWmlbBD5FR7dTYtpd2iMLwu7ytFsb0n_pOD1_ti_XAytQvJH6w6pL0saABs8y_Gj1AWONfIqGGw-2ChgItUsGpHt3yr7i4gV6bKYtU2KFcwFQ3c7bXpLjV9paptLQNwOHTjadmNcuexV443pz1NlaOP9DUjTzO2WNaiAokNtJ4wh6Emdjors844p4bCnah0o4STUYbcvRILYMVIpxrew7lcrLiA-vF8kD-Pxeb_Gna8sTIQ3gx7K1fL10Mg0wPEake4Qko29gy8AXx1qki5hEYx9Pe8CxezBfyFmA" || token == "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIn0.fyDpJVopst2qpHzs63NRWZ9zY04KrxfQmiF0zt3i-ACB38hnBo90r_PlrhMiMU8HU52_JxcBUAi5lSQHakX16EQyR0pEwZZfoCbeI0lOzpt0yrXAYyGvJC8WlE1Mm9Ehd8iUgcvvc9nL0_gRT-4RSU7kVOHOlwIRiN6fE28si22Jjtb5hf0KjebLj7BTeNnVB17SK9qMMn7VuYtRKj767FDpnZuOwNkDvb2qeL3IzbJnTYgpOVMoinHWAvR_innn9BjzCOEkFqgj6KKzQiEbVI6tbHfD-qOHHVDF1a0eERtCUuu92LesUyWJj3etgnmmNFI5EVjDtQkldQuuFgARUw");
}

BOOST_AUTO_TEST_CASE(TestParserDifferentFieldOrder512)
{
    JWTXX::JWT jwt("eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIn0.fyDpJVopst2qpHzs63NRWZ9zY04KrxfQmiF0zt3i-ACB38hnBo90r_PlrhMiMU8HU52_JxcBUAi5lSQHakX16EQyR0pEwZZfoCbeI0lOzpt0yrXAYyGvJC8WlE1Mm9Ehd8iUgcvvc9nL0_gRT-4RSU7kVOHOlwIRiN6fE28si22Jjtb5hf0KjebLj7BTeNnVB17SK9qMMn7VuYtRKj767FDpnZuOwNkDvb2qeL3IzbJnTYgpOVMoinHWAvR_innn9BjzCOEkFqgj6KKzQiEbVI6tbHfD-qOHHVDF1a0eERtCUuu92LesUyWJj3etgnmmNFI5EVjDtQkldQuuFgARUw", JWTXX::Key(JWTXX::Algorithm::RS512, "public-rsa-2048-key.pem"));

    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::RS512);
    BOOST_CHECK(!jwt.claims().empty());
    BOOST_CHECK(!jwt.header().empty());
    auto header = jwt.header();
    BOOST_CHECK_EQUAL(header["alg"], "RS512");
    BOOST_CHECK_EQUAL(header["typ"], "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss"), "madf");
    auto token = jwt.token("rsa-2048-key-pair.pem");
    // Jansson uses hashtables form JSON objects and hash function implementation reads over the boundary of the string, yet word-aligned, so actual order of header fields and claims is undefined.
    BOOST_CHECK(token == "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzUxMiJ9.eyJpc3MiOiJtYWRmIn0.G8vv-IyeoIg5SWcN1Qb3-9kLPr8tnUSbBPO32Srvce04Lfe0sEWmlbBD5FR7dTYtpd2iMLwu7ytFsb0n_pOD1_ti_XAytQvJH6w6pL0saABs8y_Gj1AWONfIqGGw-2ChgItUsGpHt3yr7i4gV6bKYtU2KFcwFQ3c7bXpLjV9paptLQNwOHTjadmNcuexV443pz1NlaOP9DUjTzO2WNaiAokNtJ4wh6Emdjors844p4bCnah0o4STUYbcvRILYMVIpxrew7lcrLiA-vF8kD-Pxeb_Gna8sTIQ3gx7K1fL10Mg0wPEake4Qko29gy8AXx1qki5hEYx9Pe8CxezBfyFmA" || token == "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIn0.fyDpJVopst2qpHzs63NRWZ9zY04KrxfQmiF0zt3i-ACB38hnBo90r_PlrhMiMU8HU52_JxcBUAi5lSQHakX16EQyR0pEwZZfoCbeI0lOzpt0yrXAYyGvJC8WlE1Mm9Ehd8iUgcvvc9nL0_gRT-4RSU7kVOHOlwIRiN6fE28si22Jjtb5hf0KjebLj7BTeNnVB17SK9qMMn7VuYtRKj767FDpnZuOwNkDvb2qeL3IzbJnTYgpOVMoinHWAvR_innn9BjzCOEkFqgj6KKzQiEbVI6tbHfD-qOHHVDF1a0eERtCUuu92LesUyWJj3etgnmmNFI5EVjDtQkldQuuFgARUw");
}

BOOST_AUTO_TEST_CASE(TestParserWithCert256)
{
    JWTXX::JWT jwt("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIn0.GpuCt3HLj3ToT8SYa-EErTgd4deISPXrAq7c_fwt3837wMtFripY1DOhEH-YLxexhFwjkHrlNRWNV7jlamS32zw4y7_lF9zlQ4AgdGOXsNPUGjPXXuCPvVr84sBGpIjki9LUFa-qTGAe1qNsCH7rwG-LF4c0BOF2tnhwXSaipgFcInoHIhoj9KQBT7kkTfmXiBTp8ITkWnWMtmVaIHay6Z3aiOu-jRDWPlzoIWwLVfAPL9ti8uKzMmUGGhpiwPgwZnIoPVgyjM6U0ahHr_tEeeBYCa-7J8gYPEpXK1TkOQq1uUpk52LbrsieZMpsSTbbybGwBmBl2FBC3tjjCc8tug", JWTXX::Key(JWTXX::Algorithm::RS256, "rsa-cert.pem"));

    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::RS256);
    BOOST_CHECK(!jwt.claims().empty());
    BOOST_CHECK(!jwt.header().empty());
    auto header = jwt.header();
    BOOST_CHECK_EQUAL(header["alg"], "RS256");
    BOOST_CHECK_EQUAL(header["typ"], "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss"), "madf");
    auto token = jwt.token("rsa-2048-key-pair.pem");
    // Jansson uses hashtables form JSON objects and hash function implementation reads over the boundary of the string, yet word-aligned, so actual order of header fields and claims is undefined.
    BOOST_CHECK(token == "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIn0.GpuCt3HLj3ToT8SYa-EErTgd4deISPXrAq7c_fwt3837wMtFripY1DOhEH-YLxexhFwjkHrlNRWNV7jlamS32zw4y7_lF9zlQ4AgdGOXsNPUGjPXXuCPvVr84sBGpIjki9LUFa-qTGAe1qNsCH7rwG-LF4c0BOF2tnhwXSaipgFcInoHIhoj9KQBT7kkTfmXiBTp8ITkWnWMtmVaIHay6Z3aiOu-jRDWPlzoIWwLVfAPL9ti8uKzMmUGGhpiwPgwZnIoPVgyjM6U0ahHr_tEeeBYCa-7J8gYPEpXK1TkOQq1uUpk52LbrsieZMpsSTbbybGwBmBl2FBC3tjjCc8tug" || token == "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJtYWRmIn0.gO-HSMMeWKCmB3xFo7pvFWVNxpo17mWTKv9H2giWXJUQhzNOc2PSxhElrz7swGmpo9m7NShGueF-SlRDBgq8olgX_NDOvzvXSlVusZg8COU_PkxEd_NolEIlAoIGXGwFfpVUiv5VY_kV2vvONns1Sifr5cJ1wIbtONhpI4B0GntvBoQCq9XgbmgRN_0pOEuMs9p4xw1FXdWXv1wgrgceHJ-1QTCRXAhA9TRAxn_MNvb2Y5ftj4j_f6FsXA4xrurNOolcNgS9Fi8xhQEJVe3nwF_RIfSdHE3F5EPDvxYX6-ce-C6Acg1acwad8LEEaYpIOIgYvyJa3nmh_2hxuEGm8g");
}

BOOST_AUTO_TEST_CASE(TestParserWithCertDifferentFieldOrder256)
{
    JWTXX::JWT jwt("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJtYWRmIn0.gO-HSMMeWKCmB3xFo7pvFWVNxpo17mWTKv9H2giWXJUQhzNOc2PSxhElrz7swGmpo9m7NShGueF-SlRDBgq8olgX_NDOvzvXSlVusZg8COU_PkxEd_NolEIlAoIGXGwFfpVUiv5VY_kV2vvONns1Sifr5cJ1wIbtONhpI4B0GntvBoQCq9XgbmgRN_0pOEuMs9p4xw1FXdWXv1wgrgceHJ-1QTCRXAhA9TRAxn_MNvb2Y5ftj4j_f6FsXA4xrurNOolcNgS9Fi8xhQEJVe3nwF_RIfSdHE3F5EPDvxYX6-ce-C6Acg1acwad8LEEaYpIOIgYvyJa3nmh_2hxuEGm8g" , JWTXX::Key(JWTXX::Algorithm::RS256, "rsa-cert.pem"));

    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::RS256);
    BOOST_CHECK(!jwt.claims().empty());
    BOOST_CHECK(!jwt.header().empty());
    auto header = jwt.header();
    BOOST_CHECK_EQUAL(header["alg"], "RS256");
    BOOST_CHECK_EQUAL(header["typ"], "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss"), "madf");
    auto token = jwt.token("rsa-2048-key-pair.pem");
    // Jansson uses hashtables form JSON objects and hash function implementation reads over the boundary of the string, yet word-aligned, so actual order of header fields and claims is undefined.
    BOOST_CHECK(token == "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIn0.GpuCt3HLj3ToT8SYa-EErTgd4deISPXrAq7c_fwt3837wMtFripY1DOhEH-YLxexhFwjkHrlNRWNV7jlamS32zw4y7_lF9zlQ4AgdGOXsNPUGjPXXuCPvVr84sBGpIjki9LUFa-qTGAe1qNsCH7rwG-LF4c0BOF2tnhwXSaipgFcInoHIhoj9KQBT7kkTfmXiBTp8ITkWnWMtmVaIHay6Z3aiOu-jRDWPlzoIWwLVfAPL9ti8uKzMmUGGhpiwPgwZnIoPVgyjM6U0ahHr_tEeeBYCa-7J8gYPEpXK1TkOQq1uUpk52LbrsieZMpsSTbbybGwBmBl2FBC3tjjCc8tug" || token == "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJtYWRmIn0.gO-HSMMeWKCmB3xFo7pvFWVNxpo17mWTKv9H2giWXJUQhzNOc2PSxhElrz7swGmpo9m7NShGueF-SlRDBgq8olgX_NDOvzvXSlVusZg8COU_PkxEd_NolEIlAoIGXGwFfpVUiv5VY_kV2vvONns1Sifr5cJ1wIbtONhpI4B0GntvBoQCq9XgbmgRN_0pOEuMs9p4xw1FXdWXv1wgrgceHJ-1QTCRXAhA9TRAxn_MNvb2Y5ftj4j_f6FsXA4xrurNOolcNgS9Fi8xhQEJVe3nwF_RIfSdHE3F5EPDvxYX6-ce-C6Acg1acwad8LEEaYpIOIgYvyJa3nmh_2hxuEGm8g");
}

BOOST_AUTO_TEST_CASE(TestParserWithCert384)
{
    JWTXX::JWT jwt( "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIn0.s8DCHwP41dmCmeXSs6cUJRAFtQqOfTtk1S54MlH06By98ybpWzhY_lAwEAI4-QAIRoPvkZPtF03Qn1ZX1pETfDKk96zPTm8mojjpBfuO-LZgiQDcStf5hByhV4YBKYY5kNfuCuGBOdtPer7Uv-41aVyoIkGhNW-YwtHM3noBaWTP6igZHztKlQs816vEFQlNp_sA5yQk7qhlhHkAAFec1Db1apQke3MGn7m1wKh16CU4lscLDFze6S80WuXwBot1ksthvutYYTeRnIHeLz3ty9pGtaVBGW8EbcaDj2biBhVHRTiOS1oeZ-O8h2Nn9sDaV5_S2OHf3BTgLOZNbih5uQ", JWTXX::Key(JWTXX::Algorithm::RS384, "rsa-cert.pem"));

    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::RS384);
    BOOST_CHECK(!jwt.claims().empty());
    BOOST_CHECK(!jwt.header().empty());
    auto header = jwt.header();
    BOOST_CHECK_EQUAL(header["alg"], "RS384");
    BOOST_CHECK_EQUAL(header["typ"], "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss"), "madf");
    auto token = jwt.token("rsa-2048-key-pair.pem");
    // Jansson uses hashtables form JSON objects and hash function implementation reads over the boundary of the string, yet word-aligned, so actual order of header fields and claims is undefined.
    BOOST_CHECK(token == "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIn0.s8DCHwP41dmCmeXSs6cUJRAFtQqOfTtk1S54MlH06By98ybpWzhY_lAwEAI4-QAIRoPvkZPtF03Qn1ZX1pETfDKk96zPTm8mojjpBfuO-LZgiQDcStf5hByhV4YBKYY5kNfuCuGBOdtPer7Uv-41aVyoIkGhNW-YwtHM3noBaWTP6igZHztKlQs816vEFQlNp_sA5yQk7qhlhHkAAFec1Db1apQke3MGn7m1wKh16CU4lscLDFze6S80WuXwBot1ksthvutYYTeRnIHeLz3ty9pGtaVBGW8EbcaDj2biBhVHRTiOS1oeZ-O8h2Nn9sDaV5_S2OHf3BTgLOZNbih5uQ" || token == "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzM4NCJ9.eyJpc3MiOiJtYWRmIn0.tU5SWVRjc2BgVdZN4heYolUFhDIc9dHOxw7zYFstZKwEbj_K_9IRsl2kJ9Nw4NXGBntkBMIp6U1cqW9xkgiH1u4IAalL0q0NBIOW5-JEqUO65iDaDLkObJY65tbDT2q-CpsCBlYpULcWaZWj-3Xjn3Z0oTItjn40c4BJ8Ra0MaKDRKZNMScMnV7mHKylsPe-0aiRWK5QMaW_4KUjKmcJHpqY0aCA1yov1RLauPhXFC3w4KU_BbLJN25fMkSNwapmPKC2NQxuGjQRglAlq-XbxMe1FKieLPGCAPJLkzm9BHkZ0mmm405jVCfxEAw5DOVRrP5xo_2mpOxjIbBXJFPWMg");
}

BOOST_AUTO_TEST_CASE(TestParserWithCertDifferentFieldOrder384)
{
    JWTXX::JWT jwt("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzM4NCJ9.eyJpc3MiOiJtYWRmIn0.tU5SWVRjc2BgVdZN4heYolUFhDIc9dHOxw7zYFstZKwEbj_K_9IRsl2kJ9Nw4NXGBntkBMIp6U1cqW9xkgiH1u4IAalL0q0NBIOW5-JEqUO65iDaDLkObJY65tbDT2q-CpsCBlYpULcWaZWj-3Xjn3Z0oTItjn40c4BJ8Ra0MaKDRKZNMScMnV7mHKylsPe-0aiRWK5QMaW_4KUjKmcJHpqY0aCA1yov1RLauPhXFC3w4KU_BbLJN25fMkSNwapmPKC2NQxuGjQRglAlq-XbxMe1FKieLPGCAPJLkzm9BHkZ0mmm405jVCfxEAw5DOVRrP5xo_2mpOxjIbBXJFPWMg", JWTXX::Key(JWTXX::Algorithm::RS384, "rsa-cert.pem"));

    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::RS384);
    BOOST_CHECK(!jwt.claims().empty());
    BOOST_CHECK(!jwt.header().empty());
    auto header = jwt.header();
    BOOST_CHECK_EQUAL(header["alg"], "RS384");
    BOOST_CHECK_EQUAL(header["typ"], "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss"), "madf");
    auto token = jwt.token("rsa-2048-key-pair.pem");
    // Jansson uses hashtables form JSON objects and hash function implementation reads over the boundary of the string, yet word-aligned, so actual order of header fields and claims is undefined.
    BOOST_CHECK(token == "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIn0.s8DCHwP41dmCmeXSs6cUJRAFtQqOfTtk1S54MlH06By98ybpWzhY_lAwEAI4-QAIRoPvkZPtF03Qn1ZX1pETfDKk96zPTm8mojjpBfuO-LZgiQDcStf5hByhV4YBKYY5kNfuCuGBOdtPer7Uv-41aVyoIkGhNW-YwtHM3noBaWTP6igZHztKlQs816vEFQlNp_sA5yQk7qhlhHkAAFec1Db1apQke3MGn7m1wKh16CU4lscLDFze6S80WuXwBot1ksthvutYYTeRnIHeLz3ty9pGtaVBGW8EbcaDj2biBhVHRTiOS1oeZ-O8h2Nn9sDaV5_S2OHf3BTgLOZNbih5uQ" || token == "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzM4NCJ9.eyJpc3MiOiJtYWRmIn0.tU5SWVRjc2BgVdZN4heYolUFhDIc9dHOxw7zYFstZKwEbj_K_9IRsl2kJ9Nw4NXGBntkBMIp6U1cqW9xkgiH1u4IAalL0q0NBIOW5-JEqUO65iDaDLkObJY65tbDT2q-CpsCBlYpULcWaZWj-3Xjn3Z0oTItjn40c4BJ8Ra0MaKDRKZNMScMnV7mHKylsPe-0aiRWK5QMaW_4KUjKmcJHpqY0aCA1yov1RLauPhXFC3w4KU_BbLJN25fMkSNwapmPKC2NQxuGjQRglAlq-XbxMe1FKieLPGCAPJLkzm9BHkZ0mmm405jVCfxEAw5DOVRrP5xo_2mpOxjIbBXJFPWMg");
}

BOOST_AUTO_TEST_CASE(TestParserWithCert512)
{
    JWTXX::JWT jwt( "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzUxMiJ9.eyJpc3MiOiJtYWRmIn0.G8vv-IyeoIg5SWcN1Qb3-9kLPr8tnUSbBPO32Srvce04Lfe0sEWmlbBD5FR7dTYtpd2iMLwu7ytFsb0n_pOD1_ti_XAytQvJH6w6pL0saABs8y_Gj1AWONfIqGGw-2ChgItUsGpHt3yr7i4gV6bKYtU2KFcwFQ3c7bXpLjV9paptLQNwOHTjadmNcuexV443pz1NlaOP9DUjTzO2WNaiAokNtJ4wh6Emdjors844p4bCnah0o4STUYbcvRILYMVIpxrew7lcrLiA-vF8kD-Pxeb_Gna8sTIQ3gx7K1fL10Mg0wPEake4Qko29gy8AXx1qki5hEYx9Pe8CxezBfyFmA", JWTXX::Key(JWTXX::Algorithm::RS512, "rsa-cert.pem"));

    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::RS512);
    BOOST_CHECK(!jwt.claims().empty());
    BOOST_CHECK(!jwt.header().empty());
    auto header = jwt.header();
    BOOST_CHECK_EQUAL(header["alg"], "RS512");
    BOOST_CHECK_EQUAL(header["typ"], "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss"), "madf");
    auto token = jwt.token("rsa-2048-key-pair.pem");
    // Jansson uses hashtables form JSON objects and hash function implementation reads over the boundary of the string, yet word-aligned, so actual order of header fields and claims is undefined.
    BOOST_CHECK(token == "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzUxMiJ9.eyJpc3MiOiJtYWRmIn0.G8vv-IyeoIg5SWcN1Qb3-9kLPr8tnUSbBPO32Srvce04Lfe0sEWmlbBD5FR7dTYtpd2iMLwu7ytFsb0n_pOD1_ti_XAytQvJH6w6pL0saABs8y_Gj1AWONfIqGGw-2ChgItUsGpHt3yr7i4gV6bKYtU2KFcwFQ3c7bXpLjV9paptLQNwOHTjadmNcuexV443pz1NlaOP9DUjTzO2WNaiAokNtJ4wh6Emdjors844p4bCnah0o4STUYbcvRILYMVIpxrew7lcrLiA-vF8kD-Pxeb_Gna8sTIQ3gx7K1fL10Mg0wPEake4Qko29gy8AXx1qki5hEYx9Pe8CxezBfyFmA" || token == "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIn0.fyDpJVopst2qpHzs63NRWZ9zY04KrxfQmiF0zt3i-ACB38hnBo90r_PlrhMiMU8HU52_JxcBUAi5lSQHakX16EQyR0pEwZZfoCbeI0lOzpt0yrXAYyGvJC8WlE1Mm9Ehd8iUgcvvc9nL0_gRT-4RSU7kVOHOlwIRiN6fE28si22Jjtb5hf0KjebLj7BTeNnVB17SK9qMMn7VuYtRKj767FDpnZuOwNkDvb2qeL3IzbJnTYgpOVMoinHWAvR_innn9BjzCOEkFqgj6KKzQiEbVI6tbHfD-qOHHVDF1a0eERtCUuu92LesUyWJj3etgnmmNFI5EVjDtQkldQuuFgARUw");
}

BOOST_AUTO_TEST_CASE(TestParserWithCertDifferentFieldOrder512)
{
    JWTXX::JWT jwt("eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIn0.fyDpJVopst2qpHzs63NRWZ9zY04KrxfQmiF0zt3i-ACB38hnBo90r_PlrhMiMU8HU52_JxcBUAi5lSQHakX16EQyR0pEwZZfoCbeI0lOzpt0yrXAYyGvJC8WlE1Mm9Ehd8iUgcvvc9nL0_gRT-4RSU7kVOHOlwIRiN6fE28si22Jjtb5hf0KjebLj7BTeNnVB17SK9qMMn7VuYtRKj767FDpnZuOwNkDvb2qeL3IzbJnTYgpOVMoinHWAvR_innn9BjzCOEkFqgj6KKzQiEbVI6tbHfD-qOHHVDF1a0eERtCUuu92LesUyWJj3etgnmmNFI5EVjDtQkldQuuFgARUw", JWTXX::Key(JWTXX::Algorithm::RS512, "rsa-cert.pem"));

    BOOST_CHECK_EQUAL(jwt.alg(), JWTXX::Algorithm::RS512);
    BOOST_CHECK(!jwt.claims().empty());
    BOOST_CHECK(!jwt.header().empty());
    auto header = jwt.header();
    BOOST_CHECK_EQUAL(header["alg"], "RS512");
    BOOST_CHECK_EQUAL(header["typ"], "JWT");
    BOOST_CHECK_EQUAL(jwt.claim("iss"), "madf");
    auto token = jwt.token("rsa-2048-key-pair.pem");
    // Jansson uses hashtables form JSON objects and hash function implementation reads over the boundary of the string, yet word-aligned, so actual order of header fields and claims is undefined.
    BOOST_CHECK(token == "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzUxMiJ9.eyJpc3MiOiJtYWRmIn0.G8vv-IyeoIg5SWcN1Qb3-9kLPr8tnUSbBPO32Srvce04Lfe0sEWmlbBD5FR7dTYtpd2iMLwu7ytFsb0n_pOD1_ti_XAytQvJH6w6pL0saABs8y_Gj1AWONfIqGGw-2ChgItUsGpHt3yr7i4gV6bKYtU2KFcwFQ3c7bXpLjV9paptLQNwOHTjadmNcuexV443pz1NlaOP9DUjTzO2WNaiAokNtJ4wh6Emdjors844p4bCnah0o4STUYbcvRILYMVIpxrew7lcrLiA-vF8kD-Pxeb_Gna8sTIQ3gx7K1fL10Mg0wPEake4Qko29gy8AXx1qki5hEYx9Pe8CxezBfyFmA" || token == "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtYWRmIn0.fyDpJVopst2qpHzs63NRWZ9zY04KrxfQmiF0zt3i-ACB38hnBo90r_PlrhMiMU8HU52_JxcBUAi5lSQHakX16EQyR0pEwZZfoCbeI0lOzpt0yrXAYyGvJC8WlE1Mm9Ehd8iUgcvvc9nL0_gRT-4RSU7kVOHOlwIRiN6fE28si22Jjtb5hf0KjebLj7BTeNnVB17SK9qMMn7VuYtRKj767FDpnZuOwNkDvb2qeL3IzbJnTYgpOVMoinHWAvR_innn9BjzCOEkFqgj6KKzQiEbVI6tbHfD-qOHHVDF1a0eERtCUuu92LesUyWJj3etgnmmNFI5EVjDtQkldQuuFgARUw");
}
