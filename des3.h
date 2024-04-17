#ifndef _DES3_H
#define _DES3_H


#ifndef UINT8
#define UINT8  unsigned char
#endif

#ifndef UINT16
#define UINT16 unsigned short
#endif

#ifndef UINT32
#define UINT32 unsigned int
#endif

typedef struct
{
    UINT32 esk[32];     /* DES encryption subkeys */
    UINT32 dsk[32];     /* DES decryption subkeys */
}
des_context;

typedef struct
{
    UINT32 esk[96];     /* Triple-DES encryption subkeys */
    UINT32 dsk[96];     /* Triple-DES decryption subkeys */
}
des3_context;

int  des_set_key( des_context *ctx, UINT8 key[8] );
void des_encrypt( des_context *ctx, UINT8 input[8], UINT8 output[8] );
void des_decrypt( des_context *ctx, UINT8 input[8], UINT8 output[8] );

int  des3_set_2keys( des3_context *ctx, UINT8 key1[8], UINT8 key2[8] );
int  des3_set_3keys( des3_context *ctx, UINT8 key1[8], UINT8 key2[8],
                                        UINT8 key3[8] );

void des3_encrypt( des3_context *ctx, UINT8 input[8], UINT8 output[8] );
void des3_decrypt( des3_context *ctx, UINT8 input[8], UINT8 output[8] );

typedef struct
{
    UINT32 esk[96];     /* Triple-DES encryption subkeys */
    UINT32 dsk[96];     /* Triple-DES decryption subkeys */
	UINT32 eiv[2];
	UINT32 div[2];
}
des3_cbc_context;
int  des3_cbc_set_keys( des3_cbc_context *ctx, UINT8 key1[8], UINT8 key2[8] );
void des3_cbc_encrypt( des3_cbc_context *ctx, UINT8 input[8], UINT8 output[8] );
void des3_cbc_decrypt( des3_cbc_context *ctx, UINT8 input[8], UINT8 output[8] );


//////////////////////////////////////////////////////////////////////////

#include <string>
#include "tool.h"
bool				DES3_Encrypt( const std::string & s2key, const std::string & splaintext, std::string & sout );//jiami
bool				DES3_Decrypt( const std::string & s2key, const std::string & sciphertext, std::string & sout );//jiemi


#endif /* des.h */

