/*
 *  Example ECDSA program
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_printf     printf
#endif

#if defined(MBEDTLS_ECDSA_C) && \
    defined(MBEDTLS_ENTROPY_C) && defined(MBEDTLS_CTR_DRBG_C)
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/sha256.h"

#include <string.h>
#endif

/*
 * Uncomment to show key and signature details
 */
#define VERBOSE

/*
 * Uncomment to force use of a specific curve
 */
#define ECPARAMS    MBEDTLS_ECP_DP_ED25519

#if !defined(ECPARAMS)
#define ECPARAMS    mbedtls_ecp_curve_list()->grp_id
#endif

#if !defined(MBEDTLS_ECDSA_C) || !defined(MBEDTLS_SHA256_C) || \
    !defined(MBEDTLS_ENTROPY_C) || !defined(MBEDTLS_CTR_DRBG_C)
int main( void )
{
    mbedtls_printf("MBEDTLS_ECDSA_C and/or MBEDTLS_SHA256_C and/or "
           "MBEDTLS_ENTROPY_C and/or MBEDTLS_CTR_DRBG_C not defined\n");
    return( 0 );
}
#else
#if defined(VERBOSE)
static void dump_buf( const char *title, unsigned char *buf, size_t len )
{
    size_t i;

    mbedtls_printf( "%s", title );
    for( i = 0; i < len; i++ )
        mbedtls_printf("%c%c", "0123456789ABCDEF" [buf[i] / 16],
                       "0123456789ABCDEF" [buf[i] % 16] );
    mbedtls_printf( "\n" );
}

static void dump_pubkey( const char *title, mbedtls_ecdsa_context *key )
{
    unsigned char buf[300];
    size_t len;

    if( mbedtls_ecp_point_write_binary( &key->grp, &key->Q,
                MBEDTLS_ECP_PF_UNCOMPRESSED, &len, buf, sizeof buf ) != 0 )
    {
        mbedtls_printf("internal error\n");
        return;
    }

    dump_buf( title, buf, len );
}
#else
#define dump_buf( a, b, c )
#define dump_pubkey( a, b )
#endif

#define MIN(a,b) (((a) > (b)) ? (b) : (a))

static uint8_t nybble2bin(const char c) {
  uint8_t b = c - '0';
  if ((c >= 'a') && (c <= 'f')) {
    b = c - 'a' + 0x0a;
  }
  else if ((c >= 'A') && (c <= 'F')) {
    b = c - 'A' + 0x0a;
  }
  return b;
}

static void hex2bin(
  uint8_t * out,
  int outLen,
  const char * const in,
  int inLen
)
{
  char * pinmalloc = NULL;
  const char * pin = in;
  const int inLen2 = 2 * ((inLen + 1) / 2);  
  if (inLen2 != inLen) {
    pinmalloc = calloc(inLen2 + 1, 1);
    memcpy(&pinmalloc[inLen2 - inLen], in, inLen);
    pin = pinmalloc;
  }

  int i = 0;
  for (int o = 0; (i < inLen) && (o < outLen); o++) {
    out[o] =  nybble2bin(pin[i + 0]) << 4;
    out[o] |= nybble2bin(pin[i + 1]) << 0;
    i += 2;
  }

  if (pinmalloc) {
    free(pinmalloc);
  }
}

#include "crypto_sign_ed25519.h"



 // Test function used by ed25519sigs
static int ed25519TestVector(
  const char szPk32[64],
  const char szSk32[64],
  const char szMsg[],
  const int  mlen,
  const char szSig[128])
{
  int ret = 0;
  uint8_t sk[64];
  uint8_t pk[32];
  uint8_t sigRef[64];
  const int msgLen = mlen / 2;
  uint8_t *msg = calloc(msgLen + 2, 1);

  hex2bin(&sk[0], 32, szSk32, 64);
  hex2bin(pk, 32, szPk32, 64);
  memcpy(&sk[32], pk, 32);
  hex2bin(&sigRef[0], 64, szSig, 128);
  hex2bin(msg, msgLen, szMsg, mlen);

  // First signature test with raw libsodium
  if (0 == ret) {
    uint8_t sig[64];

    unsigned long long siglen = 64;
    ret = crypto_sign_ed25519_detached(sig, &siglen, msg, msgLen, sk);

    if (0 == ret) {
      ret = memcmp(sig, sigRef, sizeof sig);
    }

    if (0 == ret) {
      ret = crypto_sign_ed25519_verify_detached(sig, msg, msgLen, &sk[32]);
    }
  }

  if (0 == ret) {
    uint8_t sig[64];

    mbedtls_ecdsa_context ctx_sign;
    mbedtls_ecdsa_init(&ctx_sign);

    mbedtls_ecp_group_load(&ctx_sign.grp, MBEDTLS_ECP_DP_ED25519);
    mbedtls_mpi_read_binary(&ctx_sign.d, sk, sizeof sk);
    mbedtls_mpi_read_binary(&ctx_sign.Q.X, pk, sizeof pk);    
    mbedtls_mpi_lset(&ctx_sign.Q.Z, 1);

    mbedtls_mpi r, s;
    mbedtls_mpi_init(&r); mbedtls_mpi_init(&s);
    ret = mbedtls_ecdsa_sign(&ctx_sign.grp, &r, &s, &ctx_sign.d, msg, msgLen, NULL, 0);
    if (0 == ret) {
      ret = mbedtls_mpi_write_binary(&r, sig, sizeof sig);
    }

    if (0 == ret) {
      ret = memcmp(sig, sigRef, sizeof sig);
    }

    if (0 == ret) {
      mbedtls_ecdsa_context ctx_verify;
      mbedtls_ecdsa_init(&ctx_verify);
      mbedtls_ecp_group_load(&ctx_verify.grp, MBEDTLS_ECP_DP_ED25519);
      mbedtls_mpi_read_binary(&ctx_verify.Q.X, pk, sizeof pk);
      mbedtls_mpi_lset(&ctx_verify.Q.Z, 1);

      ret = mbedtls_ecdsa_verify(&ctx_verify.grp, msg, msgLen, &ctx_verify.Q, &r, &s);

      mbedtls_ecdsa_free(&ctx_verify);
    }



    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    mbedtls_ecdsa_free(&ctx_sign);
  }

  free (msg);

#if 0
  
  sstring spk, ssk;
  CNV_AsciiHexToBinStr(sk, 64, ssk);
  EXPECT_TRUE(ssk.length() == 32);

  CNV_AsciiHexToBinStr(pk, 64, spk);
  EXPECT_TRUE(spk.length() == 32);

  sstring ssig;
  CNV_AsciiHexToBinStr(sig, 128, ssig);
  EXPECT_TRUE(ssig.length() == 64);

  sstring sm;
  CNV_AsciiHexToBinStr(m, mlen, sm);


  Ed25519SigningKey key;
  key.LoadKeysStr(&spk, &ssk);

  sstring ssigout;
  key.Sign(sm.u_str(), sm.length(), ssigout);

  EXPECT_TRUE(ssig == ssigout);

  EXPECT_TRUE(key.Verify(sm.u_str(), sm.length(), ssig));
  ssigout.u8DataPtr()[0] ^= 0x01;
  EXPECT_FALSE(key.Verify(sm.u_str(), sm.length(), ssigout));
#endif

  return ret;

}


static int test_ref_keys(void) {

    //Test Vectors for Ed25519
  int ret = 0;
    //  Below is a sequence of octets with test vectors for the the Ed25519
    //  signature algorithm.The octets are hex encoded and whitespace is
    //  inserted for readability.Private keys are 64 bytes, public keys 32
    //  bytes, message of arbitrary length, and signatures are 64 bytes.The
    //  test vectors are taken from[ED25519 - TEST - VECTORS](but we removed
    //    the public key as a suffix of the secret key, and removed the message
    //    from the signature) and [ED25519 - LIBGCRYPT - TEST - VECTORS].
    if (0 == ret)
    {
      //  ---- - TEST 1
      // SECRET KEY :
      const char sk[] = "9d61b19deffd5a60ba844af492ec2cc4"
        "4449c5697b326919703bac031cae7f60";

      // PUBLIC KEY :
      const char pk[] = "d75a980182b10ab7d54bfed3c964073a"
        "0ee172f3daa62325af021a68f707511a";

      // // MESSAGE(length 0 bytes) :
      const char m[1] = { 0 };

      // SIGNATURE:
      const char sig[] =
        "e5564300c360ac729086e2cc806e828a"
        "84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46b"
        "d25bf5f0595bbe24655141438e7a100b";

      ret = ed25519TestVector(pk, sk, m, 0, sig);
    }

    if (0 == ret)
    {
      // ---- - TEST 2
      // SECRET KEY :
      const char sk[] = "4ccd089b28ff96da9db6c346ec114e0f"
        "5b8a319f35aba624da8cf6ed4fb8a6fb";

      // PUBLIC KEY :
      const char pk[] = "3d4017c3e843895a92b70aa74d1b7ebc"
        "9c982ccf2ec4968cc0cd55f12af4660c";

      // MESSAGE(length 1 byte) :
      const char m[] = "72";

      // SIGNATURE :
      const char sig[] =
        "92a009a9f0d4cab8720e820b5f642540"
        "a2b27b5416503f8fb3762223ebdb69da"
        "085ac1e43e15996e458f3613d0f11d8c"
        "387b2eaeb4302aeeb00d291612bb0c00";

      ret = ed25519TestVector(pk, sk, m, sizeof(m) - 1, sig);
    }

    if (0 == ret)
    {
      // ---- - TEST 3
      // SECRET KEY :
      const char sk[] = "c5aa8df43f9f837bedb7442f31dcb7b1"
        "66d38535076f094b85ce3a2e0b4458f7";

      // PUBLIC KEY :
      const char pk[] = "fc51cd8e6218a1a38da47ed00230f058"
        "0816ed13ba3303ac5deb911548908025";

      // MESSAGE(length 2 bytes) :
      const char m[] = "af82";

      // SIGNATURE :
      const char sig[] =
        "6291d657deec24024827e69c3abe01a3"
        "0ce548a284743a445e3680d7db5ac3ac"
        "18ff9b538d16f290ae67f760984dc659"
        "4a7c15e9716ed28dc027beceea1ec40a";

      ret = ed25519TestVector(pk, sk, m, sizeof(m) - 1, sig);
    }

    if (0 == ret)
    {

      // ---- - TEST 1024
      // SECRET KEY :
      const char sk[] = "f5e5767cf153319517630f226876b86c"
        "8160cc583bc013744c6bf255f5cc0ee5";

      // PUBLIC KEY :
      const char pk[] = "278117fc144c72340f67d0f2316e8386"
        "ceffbf2b2428c9c51fef7c597f1d426e";

      // MESSAGE :
      const char m[] = "08b8b2b733424243760fe426a4b54908"
        "632110a66c2f6591eabd3345e3e4eb98"
        "fa6e264bf09efe12ee50f8f54e9f77b1"
        "e355f6c50544e23fb1433ddf73be84d8"
        "79de7c0046dc4996d9e773f4bc9efe57"
        "38829adb26c81b37c93a1b270b20329d"
        "658675fc6ea534e0810a4432826bf58c"
        "941efb65d57a338bbd2e26640f89ffbc"
        "1a858efcb8550ee3a5e1998bd177e93a"
        "7363c344fe6b199ee5d02e82d522c4fe"
        "ba15452f80288a821a579116ec6dad2b"
        "3b310da903401aa62100ab5d1a36553e"
        "06203b33890cc9b832f79ef80560ccb9"
        "a39ce767967ed628c6ad573cb116dbef"
        "efd75499da96bd68a8a97b928a8bbc10"
        "3b6621fcde2beca1231d206be6cd9ec7"
        "aff6f6c94fcd7204ed3455c68c83f4a4"
        "1da4af2b74ef5c53f1d8ac70bdcb7ed1"
        "85ce81bd84359d44254d95629e9855a9"
        "4a7c1958d1f8ada5d0532ed8a5aa3fb2"
        "d17ba70eb6248e594e1a2297acbbb39d"
        "502f1a8c6eb6f1ce22b3de1a1f40cc24"
        "554119a831a9aad6079cad88425de6bd"
        "e1a9187ebb6092cf67bf2b13fd65f270"
        "88d78b7e883c8759d2c4f5c65adb7553"
        "878ad575f9fad878e80a0c9ba63bcbcc"
        "2732e69485bbc9c90bfbd62481d9089b"
        "eccf80cfe2df16a2cf65bd92dd597b07"
        "07e0917af48bbb75fed413d238f5555a"
        "7a569d80c3414a8d0859dc65a46128ba"
        "b27af87a71314f318c782b23ebfe808b"
        "82b0ce26401d2e22f04d83d1255dc51a"
        "ddd3b75a2b1ae0784504df543af8969b"
        "e3ea7082ff7fc9888c144da2af58429e"
        "c96031dbcad3dad9af0dcbaaaf268cb8"
        "fcffead94f3c7ca495e056a9b47acdb7"
        "51fb73e666c6c655ade8297297d07ad1"
        "ba5e43f1bca32301651339e22904cc8c"
        "42f58c30c04aafdb038dda0847dd988d"
        "cda6f3bfd15c4b4c4525004aa06eeff8"
        "ca61783aacec57fb3d1f92b0fe2fd1a8"
        "5f6724517b65e614ad6808d6f6ee34df"
        "f7310fdc82aebfd904b01e1dc54b2927"
        "094b2db68d6f903b68401adebf5a7e08"
        "d78ff4ef5d63653a65040cf9bfd4aca7"
        "984a74d37145986780fc0b16ac451649"
        "de6188a7dbdf191f64b5fc5e2ab47b57"
        "f7f7276cd419c17a3ca8e1b939ae49e4"
        "88acba6b965610b5480109c8b17b80e1"
        "b7b750dfc7598d5d5011fd2dcc5600a3"
        "2ef5b52a1ecc820e308aa342721aac09"
        "43bf6686b64b2579376504ccc493d97e"
        "6aed3fb0f9cd71a43dd497f01f17c0e2"
        "cb3797aa2a2f256656168e6c496afc5f"
        "b93246f6b1116398a346f1a641f3b041"
        "e989f7914f90cc2c7fff357876e506b5"
        "0d334ba77c225bc307ba537152f3f161"
        "0e4eafe595f6d9d90d11faa933a15ef1"
        "369546868a7f3a45a96768d40fd9d034"
        "12c091c6315cf4fde7cb68606937380d"
        "b2eaaa707b4c4185c32eddcdd306705e"
        "4dc1ffc872eeee475a64dfac86aba41c"
        "0618983f8741c5ef68d3a101e8a3b8ca"
        "c60c905c15fc910840b94c00a0b9d0";

      // SIGNATURE :
      const char sig[] =
        "0aab4c900501b3e24d7cdf4663326a3a"
        "87df5e4843b2cbdb67cbf6e460fec350"
        "aa5371b1508f9f4528ecea23c436d94b"
        "5e8fcd4f681e30a6ac00a9704a188a03";

      ret = ed25519TestVector(pk, sk, m, sizeof(m) - 1, sig);
    }
    return ret;
}


int main( int argc, char *argv[] )
{

    test_ref_keys();

    int ret;
    mbedtls_ecdsa_context ctx_sign, ctx_verify;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_sha256_context sha256_ctx;
    unsigned char message[100];
    unsigned char hash[32];
    unsigned char sig[MBEDTLS_ECDSA_MAX_LEN];
    size_t sig_len;
    const char *pers = "ecdsa";
    ((void) argv);

    mbedtls_ecdsa_init( &ctx_sign );
    mbedtls_ecdsa_init( &ctx_verify );
    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_sha256_init( &sha256_ctx );

    memset( sig, 0, sizeof( sig ) );
    memset( message, 0x25, sizeof( message ) );
    ret = 1;

    if( argc != 1 )
    {
        mbedtls_printf( "usage: ecdsa\n" );

#if defined(_WIN32)
        mbedtls_printf( "\n" );
#endif

        goto exit;
    }

    /*
     * Generate a key pair for signing
     */
    mbedtls_printf( "\n  . Seeding the random number generator..." );
    fflush( stdout );

    mbedtls_entropy_init( &entropy );
    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
        goto exit;
    }

    mbedtls_printf( " ok\n  . Generating key pair..." );
    fflush( stdout );

    if( ( ret = mbedtls_ecdsa_genkey( &ctx_sign, ECPARAMS,
                              mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ecdsa_genkey returned %d\n", ret );
        goto exit;
    }

    mbedtls_printf( " ok (key size: %d bits)\n", (int) ctx_sign.grp.pbits );

    dump_pubkey( "  + Public key: ", &ctx_sign );

    /*
     * Compute message hash
     */
    mbedtls_printf( "  . Computing message hash..." );
    fflush( stdout );

    mbedtls_sha256_starts( &sha256_ctx, 0 );
    mbedtls_sha256_update( &sha256_ctx, message, sizeof( message ) );
    mbedtls_sha256_finish( &sha256_ctx, hash );

    mbedtls_printf( " ok\n" );

    dump_buf( "  + Hash: ", hash, sizeof( hash ) );

    /*
     * Sign message hash
     */
    mbedtls_printf( "  . Signing message hash..." );
    fflush( stdout );

    if( ( ret = mbedtls_ecdsa_write_signature( &ctx_sign, MBEDTLS_MD_SHA256,
                                       hash, sizeof( hash ),
                                       sig, &sig_len,
                                       mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ecdsa_genkey returned %d\n", ret );
        goto exit;
    }
    mbedtls_printf( " ok (signature length = %u)\n", (unsigned int) sig_len );

    dump_buf( "  + Signature: ", sig, sig_len );

    /*
     * Transfer public information to verifying context
     *
     * We could use the same context for verification and signatures, but we
     * chose to use a new one in order to make it clear that the verifying
     * context only needs the public key (Q), and not the private key (d).
     */
    mbedtls_printf( "  . Preparing verification context..." );
    fflush( stdout );

    if( ( ret = mbedtls_ecp_group_copy( &ctx_verify.grp, &ctx_sign.grp ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ecp_group_copy returned %d\n", ret );
        goto exit;
    }

    if( ( ret = mbedtls_ecp_copy( &ctx_verify.Q, &ctx_sign.Q ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ecp_copy returned %d\n", ret );
        goto exit;
    }

    ret = 0;

    /*
     * Verify signature
     */
    mbedtls_printf( " ok\n  . Verifying signature..." );
    fflush( stdout );

    if( ( ret = mbedtls_ecdsa_read_signature( &ctx_verify,
                                      hash, sizeof( hash ),
                                      sig, sig_len ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ecdsa_read_signature returned %d\n", ret );
        goto exit;
    }

    mbedtls_printf( " ok\n" );

exit:

#if defined(_WIN32)
    mbedtls_printf( "  + Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    mbedtls_ecdsa_free( &ctx_verify );
    mbedtls_ecdsa_free( &ctx_sign );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );
    mbedtls_sha256_free( &sha256_ctx );

    return( ret );
}
#endif /* MBEDTLS_ECDSA_C && MBEDTLS_ENTROPY_C && MBEDTLS_CTR_DRBG_C &&
          ECPARAMS */
