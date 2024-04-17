/*
 *  FIPS-46-3 compliant 3DES implementation
 *
 *  Copyright (C) 2001-2003  Christophe Devine
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#include <cstring>
#include "des3.h"

/* the eight DES S-boxes */

static const UINT32 DES_SB1[64] =
{
    0x01010400, 0x00000000, 0x00010000, 0x01010404,
    0x01010004, 0x00010404, 0x00000004, 0x00010000,
    0x00000400, 0x01010400, 0x01010404, 0x00000400,
    0x01000404, 0x01010004, 0x01000000, 0x00000004,
    0x00000404, 0x01000400, 0x01000400, 0x00010400,
    0x00010400, 0x01010000, 0x01010000, 0x01000404,
    0x00010004, 0x01000004, 0x01000004, 0x00010004,
    0x00000000, 0x00000404, 0x00010404, 0x01000000,
    0x00010000, 0x01010404, 0x00000004, 0x01010000,
    0x01010400, 0x01000000, 0x01000000, 0x00000400,
    0x01010004, 0x00010000, 0x00010400, 0x01000004,
    0x00000400, 0x00000004, 0x01000404, 0x00010404,
    0x01010404, 0x00010004, 0x01010000, 0x01000404,
    0x01000004, 0x00000404, 0x00010404, 0x01010400,
    0x00000404, 0x01000400, 0x01000400, 0x00000000,
    0x00010004, 0x00010400, 0x00000000, 0x01010004
};

static const UINT32 DES_SB2[64] =
{
    0x80108020, 0x80008000, 0x00008000, 0x00108020,
    0x00100000, 0x00000020, 0x80100020, 0x80008020,
    0x80000020, 0x80108020, 0x80108000, 0x80000000,
    0x80008000, 0x00100000, 0x00000020, 0x80100020,
    0x00108000, 0x00100020, 0x80008020, 0x00000000,
    0x80000000, 0x00008000, 0x00108020, 0x80100000,
    0x00100020, 0x80000020, 0x00000000, 0x00108000,
    0x00008020, 0x80108000, 0x80100000, 0x00008020,
    0x00000000, 0x00108020, 0x80100020, 0x00100000,
    0x80008020, 0x80100000, 0x80108000, 0x00008000,
    0x80100000, 0x80008000, 0x00000020, 0x80108020,
    0x00108020, 0x00000020, 0x00008000, 0x80000000,
    0x00008020, 0x80108000, 0x00100000, 0x80000020,
    0x00100020, 0x80008020, 0x80000020, 0x00100020,
    0x00108000, 0x00000000, 0x80008000, 0x00008020,
    0x80000000, 0x80100020, 0x80108020, 0x00108000
};

static const UINT32 DES_SB3[64] =
{
    0x00000208, 0x08020200, 0x00000000, 0x08020008,
    0x08000200, 0x00000000, 0x00020208, 0x08000200,
    0x00020008, 0x08000008, 0x08000008, 0x00020000,
    0x08020208, 0x00020008, 0x08020000, 0x00000208,
    0x08000000, 0x00000008, 0x08020200, 0x00000200,
    0x00020200, 0x08020000, 0x08020008, 0x00020208,
    0x08000208, 0x00020200, 0x00020000, 0x08000208,
    0x00000008, 0x08020208, 0x00000200, 0x08000000,
    0x08020200, 0x08000000, 0x00020008, 0x00000208,
    0x00020000, 0x08020200, 0x08000200, 0x00000000,
    0x00000200, 0x00020008, 0x08020208, 0x08000200,
    0x08000008, 0x00000200, 0x00000000, 0x08020008,
    0x08000208, 0x00020000, 0x08000000, 0x08020208,
    0x00000008, 0x00020208, 0x00020200, 0x08000008,
    0x08020000, 0x08000208, 0x00000208, 0x08020000,
    0x00020208, 0x00000008, 0x08020008, 0x00020200
};

static const UINT32 DES_SB4[64] =
{
    0x00802001, 0x00002081, 0x00002081, 0x00000080,
    0x00802080, 0x00800081, 0x00800001, 0x00002001,
    0x00000000, 0x00802000, 0x00802000, 0x00802081,
    0x00000081, 0x00000000, 0x00800080, 0x00800001,
    0x00000001, 0x00002000, 0x00800000, 0x00802001,
    0x00000080, 0x00800000, 0x00002001, 0x00002080,
    0x00800081, 0x00000001, 0x00002080, 0x00800080,
    0x00002000, 0x00802080, 0x00802081, 0x00000081,
    0x00800080, 0x00800001, 0x00802000, 0x00802081,
    0x00000081, 0x00000000, 0x00000000, 0x00802000,
    0x00002080, 0x00800080, 0x00800081, 0x00000001,
    0x00802001, 0x00002081, 0x00002081, 0x00000080,
    0x00802081, 0x00000081, 0x00000001, 0x00002000,
    0x00800001, 0x00002001, 0x00802080, 0x00800081,
    0x00002001, 0x00002080, 0x00800000, 0x00802001,
    0x00000080, 0x00800000, 0x00002000, 0x00802080
};

static const UINT32 DES_SB5[64] =
{
    0x00000100, 0x02080100, 0x02080000, 0x42000100,
    0x00080000, 0x00000100, 0x40000000, 0x02080000,
    0x40080100, 0x00080000, 0x02000100, 0x40080100,
    0x42000100, 0x42080000, 0x00080100, 0x40000000,
    0x02000000, 0x40080000, 0x40080000, 0x00000000,
    0x40000100, 0x42080100, 0x42080100, 0x02000100,
    0x42080000, 0x40000100, 0x00000000, 0x42000000,
    0x02080100, 0x02000000, 0x42000000, 0x00080100,
    0x00080000, 0x42000100, 0x00000100, 0x02000000,
    0x40000000, 0x02080000, 0x42000100, 0x40080100,
    0x02000100, 0x40000000, 0x42080000, 0x02080100,
    0x40080100, 0x00000100, 0x02000000, 0x42080000,
    0x42080100, 0x00080100, 0x42000000, 0x42080100,
    0x02080000, 0x00000000, 0x40080000, 0x42000000,
    0x00080100, 0x02000100, 0x40000100, 0x00080000,
    0x00000000, 0x40080000, 0x02080100, 0x40000100
};

static const UINT32 DES_SB6[64] =
{
    0x20000010, 0x20400000, 0x00004000, 0x20404010,
    0x20400000, 0x00000010, 0x20404010, 0x00400000,
    0x20004000, 0x00404010, 0x00400000, 0x20000010,
    0x00400010, 0x20004000, 0x20000000, 0x00004010,
    0x00000000, 0x00400010, 0x20004010, 0x00004000,
    0x00404000, 0x20004010, 0x00000010, 0x20400010,
    0x20400010, 0x00000000, 0x00404010, 0x20404000,
    0x00004010, 0x00404000, 0x20404000, 0x20000000,
    0x20004000, 0x00000010, 0x20400010, 0x00404000,
    0x20404010, 0x00400000, 0x00004010, 0x20000010,
    0x00400000, 0x20004000, 0x20000000, 0x00004010,
    0x20000010, 0x20404010, 0x00404000, 0x20400000,
    0x00404010, 0x20404000, 0x00000000, 0x20400010,
    0x00000010, 0x00004000, 0x20400000, 0x00404010,
    0x00004000, 0x00400010, 0x20004010, 0x00000000,
    0x20404000, 0x20000000, 0x00400010, 0x20004010
};

static const UINT32 DES_SB7[64] =
{
    0x00200000, 0x04200002, 0x04000802, 0x00000000,
    0x00000800, 0x04000802, 0x00200802, 0x04200800,
    0x04200802, 0x00200000, 0x00000000, 0x04000002,
    0x00000002, 0x04000000, 0x04200002, 0x00000802,
    0x04000800, 0x00200802, 0x00200002, 0x04000800,
    0x04000002, 0x04200000, 0x04200800, 0x00200002,
    0x04200000, 0x00000800, 0x00000802, 0x04200802,
    0x00200800, 0x00000002, 0x04000000, 0x00200800,
    0x04000000, 0x00200800, 0x00200000, 0x04000802,
    0x04000802, 0x04200002, 0x04200002, 0x00000002,
    0x00200002, 0x04000000, 0x04000800, 0x00200000,
    0x04200800, 0x00000802, 0x00200802, 0x04200800,
    0x00000802, 0x04000002, 0x04200802, 0x04200000,
    0x00200800, 0x00000000, 0x00000002, 0x04200802,
    0x00000000, 0x00200802, 0x04200000, 0x00000800,
    0x04000002, 0x04000800, 0x00000800, 0x00200002
};

static const UINT32 DES_SB8[64] =
{
    0x10001040, 0x00001000, 0x00040000, 0x10041040,
    0x10000000, 0x10001040, 0x00000040, 0x10000000,
    0x00040040, 0x10040000, 0x10041040, 0x00041000,
    0x10041000, 0x00041040, 0x00001000, 0x00000040,
    0x10040000, 0x10000040, 0x10001000, 0x00001040,
    0x00041000, 0x00040040, 0x10040040, 0x10041000,
    0x00001040, 0x00000000, 0x00000000, 0x10040040,
    0x10000040, 0x10001000, 0x00041040, 0x00040000,
    0x00041040, 0x00040000, 0x10041000, 0x00001000,
    0x00000040, 0x10040040, 0x00001000, 0x00041040,
    0x10001000, 0x00000040, 0x10000040, 0x10040000,
    0x10040040, 0x10000000, 0x00040000, 0x10001040,
    0x00000000, 0x10041040, 0x00040040, 0x10000040,
    0x10040000, 0x10001000, 0x10001040, 0x00000000,
    0x10041040, 0x00041000, 0x00041000, 0x00001040,
    0x00001040, 0x00040040, 0x10000000, 0x10041000
};

/* PC1: left and right halves bit-swap */

static const UINT32 DES_LHs[16] =
{
    0x00000000, 0x00000001, 0x00000100, 0x00000101,
    0x00010000, 0x00010001, 0x00010100, 0x00010101,
    0x01000000, 0x01000001, 0x01000100, 0x01000101,
    0x01010000, 0x01010001, 0x01010100, 0x01010101
};

static const UINT32 DES_RHs[16] =
{
    0x00000000, 0x01000000, 0x00010000, 0x01010000,
    0x00000100, 0x01000100, 0x00010100, 0x01010100,
    0x00000001, 0x01000001, 0x00010001, 0x01010001,
    0x00000101, 0x01000101, 0x00010101, 0x01010101,
};

/* platform-independant 32-bit integer manipulation macros */
#ifdef LITTLE_END

#define DES_GET_UINT32(n,b,i)                       \
{                                               \
    (n) = ( (UINT32) (b)[(i) + 3] << 24 )       \
        | ( (UINT32) (b)[(i) + 2] << 16 )       \
        | ( (UINT32) (b)[(i) + 1] <<  8 )       \
        | ( (UINT32) (b)[(i) + 0]       );      \
}

#define DES_PUT_UINT32(n,b,i)                       \
{                                               \
    (b)[(i) + 3] = (UINT8) ( (n) >> 24 );       \
    (b)[(i) + 2] = (UINT8) ( (n) >> 16 );       \
    (b)[(i) + 1] = (UINT8) ( (n) >>  8 );       \
    (b)[(i) + 0 ] = (UINT8) ( (n)       );       \
}


#else
#define DES_GET_UINT32(n,b,i)                       \
{                                               \
    (n) = ( (UINT32) (b)[(i)    ] << 24 )       \
        | ( (UINT32) (b)[(i) + 1] << 16 )       \
        | ( (UINT32) (b)[(i) + 2] <<  8 )       \
        | ( (UINT32) (b)[(i) + 3]       );      \
}

#define DES_PUT_UINT32(n,b,i)                       \
{                                               \
    (b)[(i)    ] = (UINT8) ( (n) >> 24 );       \
    (b)[(i) + 1] = (UINT8) ( (n) >> 16 );       \
    (b)[(i) + 2] = (UINT8) ( (n) >>  8 );       \
    (b)[(i) + 3] = (UINT8) ( (n)       );       \
}

#endif 


/* Initial Permutation macro */

#define DES_IP(X,Y)                                             \
{                                                               \
    T = ((X >>  4) ^ Y) & 0x0F0F0F0F; Y ^= T; X ^= (T <<  4);   \
    T = ((X >> 16) ^ Y) & 0x0000FFFF; Y ^= T; X ^= (T << 16);   \
    T = ((Y >>  2) ^ X) & 0x33333333; X ^= T; Y ^= (T <<  2);   \
    T = ((Y >>  8) ^ X) & 0x00FF00FF; X ^= T; Y ^= (T <<  8);   \
    Y = ((Y << 1) | (Y >> 31)) & 0xFFFFFFFF;                    \
    T = (X ^ Y) & 0xAAAAAAAA; Y ^= T; X ^= T;                   \
    X = ((X << 1) | (X >> 31)) & 0xFFFFFFFF;                    \
}

/* Final Permutation macro */

#define DES_FP(X,Y)                                             \
{                                                               \
    X = ((X << 31) | (X >> 1)) & 0xFFFFFFFF;                    \
    T = (X ^ Y) & 0xAAAAAAAA; X ^= T; Y ^= T;                   \
    Y = ((Y << 31) | (Y >> 1)) & 0xFFFFFFFF;                    \
    T = ((Y >>  8) ^ X) & 0x00FF00FF; X ^= T; Y ^= (T <<  8);   \
    T = ((Y >>  2) ^ X) & 0x33333333; X ^= T; Y ^= (T <<  2);   \
    T = ((X >> 16) ^ Y) & 0x0000FFFF; Y ^= T; X ^= (T << 16);   \
    T = ((X >>  4) ^ Y) & 0x0F0F0F0F; Y ^= T; X ^= (T <<  4);   \
}

/* DES round macro */

#define DES_ROUND(X,Y)                          \
{                                               \
    T = *SK++ ^ X;                              \
    Y ^= DES_SB8[ (T      ) & 0x3F ] ^              \
         DES_SB6[ (T >>  8) & 0x3F ] ^              \
         DES_SB4[ (T >> 16) & 0x3F ] ^              \
         DES_SB2[ (T >> 24) & 0x3F ];               \
                                                \
    T = *SK++ ^ ((X << 28) | (X >> 4));         \
    Y ^= DES_SB7[ (T      ) & 0x3F ] ^              \
         DES_SB5[ (T >>  8) & 0x3F ] ^              \
         DES_SB3[ (T >> 16) & 0x3F ] ^              \
         DES_SB1[ (T >> 24) & 0x3F ];               \
}

/* DES key schedule */

int des_main_ks( UINT32 SK[32], UINT8 key[8] )
{
    int i;
    UINT32 X, Y, T;

    DES_GET_UINT32( X, key, 0 );
    DES_GET_UINT32( Y, key, 4 );

    /* Permuted Choice 1 */

    T =  ((Y >>  4) ^ X) & 0x0F0F0F0F;  X ^= T; Y ^= (T <<  4);
    T =  ((Y      ) ^ X) & 0x10101010;  X ^= T; Y ^= (T      );

    X =   (DES_LHs[ (X      ) & 0xF] << 3) | (DES_LHs[ (X >>  8) & 0xF ] << 2)
        | (DES_LHs[ (X >> 16) & 0xF] << 1) | (DES_LHs[ (X >> 24) & 0xF ]     )
        | (DES_LHs[ (X >>  5) & 0xF] << 7) | (DES_LHs[ (X >> 13) & 0xF ] << 6)
        | (DES_LHs[ (X >> 21) & 0xF] << 5) | (DES_LHs[ (X >> 29) & 0xF ] << 4);

    Y =   (DES_RHs[ (Y >>  1) & 0xF] << 3) | (DES_RHs[ (Y >>  9) & 0xF ] << 2)
        | (DES_RHs[ (Y >> 17) & 0xF] << 1) | (DES_RHs[ (Y >> 25) & 0xF ]     )
        | (DES_RHs[ (Y >>  4) & 0xF] << 7) | (DES_RHs[ (Y >> 12) & 0xF ] << 6)
        | (DES_RHs[ (Y >> 20) & 0xF] << 5) | (DES_RHs[ (Y >> 28) & 0xF ] << 4);

    X &= 0x0FFFFFFF;
    Y &= 0x0FFFFFFF;

    /* calculate subkeys */

    for( i = 0; i < 16; i++ )
    {
        if( i < 2 || i == 8 || i == 15 )
        {
            X = ((X <<  1) | (X >> 27)) & 0x0FFFFFFF;
            Y = ((Y <<  1) | (Y >> 27)) & 0x0FFFFFFF;
        }
        else
        {
            X = ((X <<  2) | (X >> 26)) & 0x0FFFFFFF;
            Y = ((Y <<  2) | (Y >> 26)) & 0x0FFFFFFF;
        }

        *SK++ =   ((X <<  4) & 0x24000000) | ((X << 28) & 0x10000000)
                | ((X << 14) & 0x08000000) | ((X << 18) & 0x02080000)
                | ((X <<  6) & 0x01000000) | ((X <<  9) & 0x00200000)
                | ((X >>  1) & 0x00100000) | ((X << 10) & 0x00040000)
                | ((X <<  2) & 0x00020000) | ((X >> 10) & 0x00010000)
                | ((Y >> 13) & 0x00002000) | ((Y >>  4) & 0x00001000)
                | ((Y <<  6) & 0x00000800) | ((Y >>  1) & 0x00000400)
                | ((Y >> 14) & 0x00000200) | ((Y      ) & 0x00000100)
                | ((Y >>  5) & 0x00000020) | ((Y >> 10) & 0x00000010)
                | ((Y >>  3) & 0x00000008) | ((Y >> 18) & 0x00000004)
                | ((Y >> 26) & 0x00000002) | ((Y >> 24) & 0x00000001);

        *SK++ =   ((X << 15) & 0x20000000) | ((X << 17) & 0x10000000)
                | ((X << 10) & 0x08000000) | ((X << 22) & 0x04000000)
                | ((X >>  2) & 0x02000000) | ((X <<  1) & 0x01000000)
                | ((X << 16) & 0x00200000) | ((X << 11) & 0x00100000)
                | ((X <<  3) & 0x00080000) | ((X >>  6) & 0x00040000)
                | ((X << 15) & 0x00020000) | ((X >>  4) & 0x00010000)
                | ((Y >>  2) & 0x00002000) | ((Y <<  8) & 0x00001000)
                | ((Y >> 14) & 0x00000808) | ((Y >>  9) & 0x00000400)
                | ((Y      ) & 0x00000200) | ((Y <<  7) & 0x00000100)
                | ((Y >>  7) & 0x00000020) | ((Y >>  3) & 0x00000011)
                | ((Y <<  2) & 0x00000004) | ((Y >> 21) & 0x00000002);
    }

    return( 0 );
}

int des_set_key( des_context *ctx, UINT8 key[8] )
{
    int i;

    /* setup encryption subkeys */

    des_main_ks( ctx->esk, key );

    /* setup decryption subkeys */

    for( i = 0; i < 32; i += 2 )
    {
        ctx->dsk[i    ] = ctx->esk[30 - i];
        ctx->dsk[i + 1] = ctx->esk[31 - i];
    }

    return( 0 );
}

/* DES 64-bit block encryption/decryption */

void des_crypt( UINT32 SK[32], UINT8 input[8], UINT8 output[8] )
{
    UINT32 X, Y, T, i;

    DES_GET_UINT32( X, input, 0 );
    DES_GET_UINT32( Y, input, 4 );

    DES_IP( X, Y );

    for ( i = 0; i < 8; i++ )
    {
        DES_ROUND( Y, X );  DES_ROUND( X, Y );
    }
    /*
    DES_ROUND( Y, X );  DES_ROUND( X, Y );
    DES_ROUND( Y, X );  DES_ROUND( X, Y );
    DES_ROUND( Y, X );  DES_ROUND( X, Y );
    DES_ROUND( Y, X );  DES_ROUND( X, Y );
    DES_ROUND( Y, X );  DES_ROUND( X, Y );
    DES_ROUND( Y, X );  DES_ROUND( X, Y );
    DES_ROUND( Y, X );  DES_ROUND( X, Y );
    DES_ROUND( Y, X );  DES_ROUND( X, Y );
    */
    DES_FP( Y, X );

    DES_PUT_UINT32( Y, output, 0 );
    DES_PUT_UINT32( X, output, 4 );
}

void des_encrypt( des_context *ctx, UINT8 input[8], UINT8 output[8] )
{
    des_crypt( ctx->esk, input, output );
}

void des_decrypt( des_context *ctx, UINT8 input[8], UINT8 output[8] )
{
    des_crypt( ctx->dsk, input, output );
}


/* Triple-DES 64-bit block encryption/decryption */

void des3_crypt( UINT32 SK[96], UINT32* XX,UINT32* YY )
{
    UINT32 T, i;

    UINT32 X = *XX,Y = *YY;

    DES_IP( X, Y );

    for ( i = 0; i < 8; i++ )
    {
        DES_ROUND( Y, X );  DES_ROUND( X, Y );
    }
    /*
    DES_ROUND( Y, X );  DES_ROUND( X, Y );
    DES_ROUND( Y, X );  DES_ROUND( X, Y );
    DES_ROUND( Y, X );  DES_ROUND( X, Y );
    DES_ROUND( Y, X );  DES_ROUND( X, Y );
    DES_ROUND( Y, X );  DES_ROUND( X, Y );
    DES_ROUND( Y, X );  DES_ROUND( X, Y );
    DES_ROUND( Y, X );  DES_ROUND( X, Y );
    DES_ROUND( Y, X );  DES_ROUND( X, Y );
    */

    for ( i = 0; i < 8; i++ )
    {
        DES_ROUND( X, Y );  DES_ROUND( Y, X );
    }
    /*
    DES_ROUND( X, Y );  DES_ROUND( Y, X );
    DES_ROUND( X, Y );  DES_ROUND( Y, X );
    DES_ROUND( X, Y );  DES_ROUND( Y, X );
    DES_ROUND( X, Y );  DES_ROUND( Y, X );
    DES_ROUND( X, Y );  DES_ROUND( Y, X );
    DES_ROUND( X, Y );  DES_ROUND( Y, X );
    DES_ROUND( X, Y );  DES_ROUND( Y, X );
    DES_ROUND( X, Y );  DES_ROUND( Y, X );
    */

    for ( i = 0; i < 8; i++ )
    {
        DES_ROUND( Y, X );  DES_ROUND( X, Y );
    }
    /*
    DES_ROUND( Y, X );  DES_ROUND( X, Y );
    DES_ROUND( Y, X );  DES_ROUND( X, Y );
    DES_ROUND( Y, X );  DES_ROUND( X, Y );
    DES_ROUND( Y, X );  DES_ROUND( X, Y );
    DES_ROUND( Y, X );  DES_ROUND( X, Y );
    DES_ROUND( Y, X );  DES_ROUND( X, Y );
    DES_ROUND( Y, X );  DES_ROUND( X, Y );
    DES_ROUND( Y, X );  DES_ROUND( X, Y );
    */

    DES_FP( Y, X );

    *XX = X;*YY = Y;
}

int  des3_cbc_set_keys( des3_cbc_context *ctx, UINT8 key1[8], UINT8 key2[8] )
{
	int i;

    des_main_ks( ctx->esk     , key1 );
    des_main_ks( ctx->dsk + 32, key2 );

    for( i = 0; i < 32; i += 2 )
    {
        ctx->dsk[i     ] = ctx->esk[30 - i];
        ctx->dsk[i +  1] = ctx->esk[31 - i];

        ctx->esk[i + 32] = ctx->dsk[62 - i];
        ctx->esk[i + 33] = ctx->dsk[63 - i];

        ctx->esk[i + 64] = ctx->esk[     i];
        ctx->esk[i + 65] = ctx->esk[ 1 + i];

        ctx->dsk[i + 64] = ctx->dsk[     i];
        ctx->dsk[i + 65] = ctx->dsk[ 1 + i];
    }
	ctx->eiv[0] = ctx->eiv[1] = ctx->div[0] = ctx->div[1] = 0;
    return( 0 );
}


void des3_cbc_encrypt( des3_cbc_context *ctx, UINT8 input[8], UINT8 output[8] )
{
	UINT32 X, Y;
	DES_GET_UINT32( X, input, 0 );
    DES_GET_UINT32( Y, input, 4 );
	X ^= ctx->eiv[0];
	Y ^= ctx->eiv[1];
    des3_crypt( ctx->esk, &X,&Y );
	ctx->eiv[0] = X;
	ctx->eiv[1] = Y;
	DES_PUT_UINT32( Y, output, 0 );
    DES_PUT_UINT32( X, output, 4 );
}
void des3_cbc_decrypt( des3_cbc_context *ctx, UINT8 input[8], UINT8 output[8] )
{
	UINT32 X, Y;
	DES_GET_UINT32( X, input, 0 );
    DES_GET_UINT32( Y, input, 4 );
    des3_crypt( ctx->dsk, &X,&Y );
	X ^= ctx->div[0];
	Y ^= ctx->div[1];
	DES_GET_UINT32( ctx->div[0], input, 0 );
    DES_GET_UINT32( ctx->div[1], input, 4 );
	DES_PUT_UINT32( Y, output, 0 );
    DES_PUT_UINT32( X, output, 4 );
}



int des3_set_2keys( des3_context *ctx, UINT8 key1[8], UINT8 key2[8] )
{
    int i;

    des_main_ks( ctx->esk     , key1 );
    des_main_ks( ctx->dsk + 32, key2 );

    for( i = 0; i < 32; i += 2 )
    {
        ctx->dsk[i     ] = ctx->esk[30 - i];
        ctx->dsk[i +  1] = ctx->esk[31 - i];

        ctx->esk[i + 32] = ctx->dsk[62 - i];
        ctx->esk[i + 33] = ctx->dsk[63 - i];

        ctx->esk[i + 64] = ctx->esk[     i];
        ctx->esk[i + 65] = ctx->esk[ 1 + i];

        ctx->dsk[i + 64] = ctx->dsk[     i];
        ctx->dsk[i + 65] = ctx->dsk[ 1 + i];
    }

    return( 0 );
}

int des3_set_3keys( des3_context *ctx, UINT8 key1[8], UINT8 key2[8],
                                       UINT8 key3[8] )
{
    int i;

    des_main_ks( ctx->esk     , key1 );
    des_main_ks( ctx->dsk + 32, key2 );
    des_main_ks( ctx->esk + 64, key3 );

    for( i = 0; i < 32; i += 2 )
    {
        ctx->dsk[i     ] = ctx->esk[94 - i];
        ctx->dsk[i +  1] = ctx->esk[95 - i];

        ctx->esk[i + 32] = ctx->dsk[62 - i];
        ctx->esk[i + 33] = ctx->dsk[63 - i];

        ctx->dsk[i + 64] = ctx->esk[30 - i];
        ctx->dsk[i + 65] = ctx->esk[31 - i];
    }

    return( 0 );
}

void des3_encrypt( des3_context *ctx, UINT8 input[8], UINT8 output[8] )
{
    UINT32 X, Y;
    DES_GET_UINT32( X, input, 0 );
    DES_GET_UINT32( Y, input, 4 );
    des3_crypt( ctx->esk, &X, &Y );
	DES_PUT_UINT32( Y, output, 0 );
    DES_PUT_UINT32( X, output, 4 );

}

void des3_decrypt( des3_context *ctx, UINT8 input[8], UINT8 output[8] )
{
    UINT32 X, Y;
    DES_GET_UINT32( X, input, 0 );
    DES_GET_UINT32( Y, input, 4 );
    des3_crypt( ctx->dsk, &X, &Y );
	DES_PUT_UINT32( Y, output, 0 );
    DES_PUT_UINT32( X, output, 4 );
}

//////////////////////////////////////////////////////////////////////////


bool DES3_Encrypt( const std::string & s2key, const std::string & splaintext, std::string & sout )
{
	if ( s2key.length() < 32 )
		return false;

	//ready enc
	std::string s2key_hex;
	hex_to_str( s2key, s2key_hex );
	des3_context ctx3;
	memset( & ctx3, 0x00, sizeof( des3_context ) );
	UINT8 uchr1[ 8 ], uchr2[ 8 ];
	memcpy( uchr1, s2key_hex.c_str(), 8 );
	memcpy( uchr2, s2key_hex.c_str() + 8, 8 );
	des3_set_2keys( &ctx3, uchr1, uchr2 );

	//do enc
	size_t nlen = splaintext.length();
	for ( size_t i = 0; i < nlen; i += 8 )
	{
		memset( uchr1, 0x00, 8 );
		memcpy( uchr1, splaintext.c_str() + i, ( ( nlen - i ) >= 8 ? 8 : ( nlen - i ) ) );
		des3_encrypt( & ctx3, uchr1, uchr2 );
		sout.append( ( char * ) uchr2, 8 );
	}

	return true;
}
bool DES3_Decrypt( const std::string & s2key, const std::string & sciphertext, std::string & sout )
{
	if ( s2key.length() < 32 )
		return false;

	//ready enc
	std::string s2key_hex;
	hex_to_str( s2key, s2key_hex );
	des3_context ctx3;
	memset( & ctx3, 0x00, sizeof( des3_context ) );
	UINT8 uchr1[ 8 ], uchr2[ 8 ];
	memcpy( uchr1, s2key_hex.c_str(), 8 );
	memcpy( uchr2, s2key_hex.c_str() + 8, 8 );
	des3_set_2keys( &ctx3, uchr1, uchr2 );

	//do enc
	size_t nlen = sciphertext.length();
	for ( size_t i = 0; i < nlen; i += 8 )
	{
		memset( uchr1, 0x00, 8 );
		memcpy( uchr1, sciphertext.c_str() + i, ( ( nlen - i ) >= 8 ? 8 : ( nlen - i ) ) );
		des3_decrypt( & ctx3, uchr1, uchr2 );
		sout.append( ( char * ) uchr2, 8 );
	}

	return true;
}
