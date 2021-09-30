#include <assert.h>
#include "fpe_util.h"

// quick power: result = x ^ e
void pow_uv(BIGNUM *pow_u, BIGNUM *pow_v, unsigned int x, int u, int v, BN_CTX *ctx)
{
    BN_CTX_start(ctx);
    BIGNUM *base = BN_CTX_get(ctx),
           *e = BN_CTX_get(ctx);

    BN_set_word(base, x);
    if (u > v) {
        /*Set v in e.*/
        BN_set_word(e, v);
        /*pow_v = base ^ e*/
        BN_exp(pow_v, base, e, ctx);
        /* pow_u = base ^ e */
        BN_mul(pow_u, pow_v, base, ctx);
    } else {
        BN_set_word(e, u);
        BN_exp(pow_u, base, e, ctx);
        if (u == v)    BN_copy(pow_v, pow_u);
        else    BN_mul(pow_v, pow_u, base, ctx);
    }

    BN_CTX_end(ctx);
    return;
}
