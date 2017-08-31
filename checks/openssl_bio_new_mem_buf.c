#include <openssl/bio.h>

int main()
{
    BIO* bio = BIO_new_mem_buf("abc", 3);
    return 0;
}
