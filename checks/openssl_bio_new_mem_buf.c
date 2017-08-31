#include <openssl/bio.h>

int main()
{
    const char* buf = "abc";
    BIO* bio = BIO_new_mem_buf(buf, 3);
    return 0;
}
