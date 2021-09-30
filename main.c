#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <fpe.h>
#include <math.h>

typedef unsigned int long long uint64t;

#define GET_TWEAK(ccn)   ((ccn & 0x000000000000FFFF) | ( (ccn & 0xFF00000000000000)>>40 ));

#define GET_1_TWEAK(ccn)  ((ccn & 0xFFFF000000000000) >> 48);
#define GET_2_TWEAK(ccn)   (ccn & 0x000000000000FFFF);

#define GET_MID_NUM(ccn)  ((ccn & 0x000000000000FFFF) | (ccn & 0xFFFF000000000000) | (ccn & 0x000000FFFFFF0000) );

#define GET_PLAIN_TXT(ccn)   ((ccn & 0x000000FFFFFF0000) >> 16);

#define GET_CCN_CIPHERED_IN_PLACE(ccn ,cipher) ((ccn & 0x000000000000FFFF) | (ccn & 0xFFFFFF0000000000) | ((cipher<<0x10) & 0x000000FFFFFF0000) )

/* Get each bit, do addition, if it is less than 10 print as it is else print the modulo 10 of it. */
uint64t i, j, o, l, m, n ;
#define GET_BIT_WISE_ADD_MOD_10(a,b) ((((i = (((a & 0xF00000) >> 20)+ ((b & 0xF00000) >> 20))) < 10 ? i : i % 10 ) << 20) | \
                                      (((j = (((a & 0x0F0000) >> 16)+ ((b & 0x0F0000) >> 16))) < 10 ? j : j % 10 ) << 16) | \
                                      (((o = (((a & 0x00F000) >> 12)+ ((b & 0x00F000) >> 12))) < 10 ? o : o % 10 ) << 12) | \
                                      (((l = (((a & 0x000F00) >> 8)+ ((b & 0x000F00) >> 8))) < 10 ? l : l % 10 ) << 8) | \
                                      (((m = (((a & 0x0000F0) >> 4)+ ((b & 0x0000F0) >> 4))) < 10 ? m : m % 10 ) << 4) | \
                                      (((n = (((a & 0x00000F) >> 0)+ ((b & 0x00000F) >> 0))) < 10 ? n : n % 10 ) << 0));

/* convert 2 hex chars to single hex char. And result length will be input/2 */
void hex2chars(unsigned char hex[], unsigned char result[])
{
    int len = strlen(hex);
    unsigned char temp[3];
    temp[2] = 0x00;

    int j = 0;
    for (int i = 0; i < len; i += 2) {
        temp[0] = hex[i];
        temp[1] = hex[i + 1];
        result[j] = (char)strtol(temp, NULL, 16);
        ++j;
    }
}

/* convert characters to integer number with base 10. Eg: '1' is converted to 1 */
void map_chars(unsigned char str[], unsigned int result[])
{
    int len = strlen(str);

    for (int i = 0; i < len; ++i)
        if (str[i] >= 'a')
            result[i] = str[i] - 'a' + 10;
        else
            result[i] = str[i] - '0';
}

void inverse_map_chars(unsigned result[], unsigned char str[], int len)
{
    for (int i = 0; i < len; ++i)
        if (result[i] < 10)
            str[i] = result[i] + '0';
        else 
            str[i] = result[i] - 10 + 'a';

    str[len] = 0x00;
}

int main(int argc, char *argv[])
{
    if (argc != 3) {
        printf("Usage: %s <key:encryption key (AES 128 bit, 192 bits or 256 bits)> <plaintext>\n", argv[0]);
        return 0;
    }

    unsigned char k[100],
                  t[100],
                  result[100], t_hex[100];

    uint64t ccn, twk, plain, tplain, ccn_ciphered;

    /* Length of the plain text */
    int xlen = 6,
    /* Length of the Key */
        klen = strlen(argv[1]) / 2,
    /* Length of the tweak */
        tlen = 6 / 2,
        radix = 10;

    unsigned int x[100], y[xlen], tmp, key_in_decimal[100], ccn_in_ascii[100];
    char twk_hex[100];
    char tplain_hex[100] = {0};

    if( !((strlen(argv[1]) == 32) ^ (strlen(argv[1]) == 48) ^ (strlen(argv[1]) ==64))) {
        printf("\nPlease enter a valid keylength (AES 128 bit, 192 bits or 256 bits) i.e. 32, 48, 64 digits in HEX\n");
        return 0;
    }

    for (int i = 0; i < strlen(argv[1]); i++) {
        if (!((argv[1][i] <= 'f' && argv[1][i] >= 'a') || (argv[1][i] <= 'F' && argv[1][i] >= 'A') || (argv[1][i] >= '0' && argv[1][i] <= '9')))
        {
            printf("\nThe key doesnot contain alphanumeric characters. Please enter the alphanumeric key with (AES 128 bit, 192 bits or 256 bits) i.e. 32, 48, 64 digits in HEX\n");
            return 0;
        }
    }

    for (int i = 0; i < strlen(argv[2]); i++) {
        if((argv[2][i] < '0' || argv[2][i] > '9') || strlen(argv[2]) != 16)
        {
            printf("\nPlease enter the a valid Credit card number!!!");
            return 0;
        }
    }

    ccn = strtoull(argv[2], NULL, 16);
    twk = GET_TWEAK(ccn);
    plain = GET_PLAIN_TXT(ccn);
    tplain = GET_BIT_WISE_ADD_MOD_10(twk, plain);
    printf ("\nEntered NUMBER: %.16llx, TWEAK: %.06llx, PLAIN_TXT:%.06llx, TWEAK+PLAIN_TXT:%.06llx \n", ccn, twk, plain, tplain);

    sprintf(twk_hex, "%.06llx", twk);
    sprintf(tplain_hex, "%.06llx", tplain);

    hex2chars(argv[1], k);
    hex2chars(twk_hex, t);
    map_chars(tplain_hex, x);

    /* Radix should not become greater than the each element of the plain text. */
    for (int i = 0; i < xlen; ++i) {
       assert((x[i] < radix) && "failed because of incorrect radix. Please input valid radix in the program" );
    }

    FPE_KEY ff1;

    printf("key:");
    for (int i = 0; i < klen; ++i)    printf(" %02x", k[i]);
    puts("");
    if (tlen)    printf("tweak:");
    for (int i = 0; i < tlen; ++i)    printf(" %02x", t[i]);
    if (tlen)    puts("");

    FPE_set_ff1_key(k, klen * 8, t, tlen, radix, &ff1);

    printf("\n\n");

    printf("\n========== DEMONSTRATING FF1 FORMAT PRESERVING ENCRYPTION ==========\n");
    printf("\n========== ENCRYPTION DONE!! ==========\n");
    FPE_ff1_encrypt(x, y, xlen, &ff1, FPE_ENCRYPT);

    printf("ciphertext(numeral string):");
    for (int i = 0; i < xlen; ++i)    printf(" %d", y[i]);
    printf("\n");

    memset(x, 0, sizeof(x));
    FPE_ff1_encrypt(y, x, xlen, &ff1, FPE_DECRYPT);

    printf("\n========== DECRYPTION DONE!! ==========\n");
    printf("plaintext:");
    for (int i = 0; i < xlen; ++i)    printf(" %d", x[i]);
    printf("\n\n");

    inverse_map_chars(y, result, xlen);
    ccn_ciphered = strtoull(result, NULL, 16);

    FPE_unset_ff1_key(&ff1);
    printf("\nCCN ciphered: %.016llx\n", GET_CCN_CIPHERED_IN_PLACE(ccn, ccn_ciphered));

    return 0;
}

