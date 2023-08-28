set (TOMCRYPT_FOLDER ${CMAKE_CURRENT_SOURCE_DIR}/libtomcrypt)

set (TOMCRYPT_SOURCES
    ${TOMCRYPT_FOLDER}/src/ciphers/aes/aes.c
    ${TOMCRYPT_FOLDER}/src/ciphers/anubis.c
    ${TOMCRYPT_FOLDER}/src/ciphers/blowfish.c
    ${TOMCRYPT_FOLDER}/src/ciphers/cast5.c
    ${TOMCRYPT_FOLDER}/src/ciphers/des.c
    ${TOMCRYPT_FOLDER}/src/ciphers/kasumi.c
    ${TOMCRYPT_FOLDER}/src/ciphers/khazad.c
    ${TOMCRYPT_FOLDER}/src/ciphers/kseed.c
    ${TOMCRYPT_FOLDER}/src/ciphers/multi2.c
    ${TOMCRYPT_FOLDER}/src/ciphers/noekeon.c
    ${TOMCRYPT_FOLDER}/src/ciphers/rc2.c
    ${TOMCRYPT_FOLDER}/src/ciphers/rc5.c
    ${TOMCRYPT_FOLDER}/src/ciphers/rc6.c
    ${TOMCRYPT_FOLDER}/src/ciphers/safer/safer.c
    ${TOMCRYPT_FOLDER}/src/ciphers/safer/saferp.c
    ${TOMCRYPT_FOLDER}/src/ciphers/safer/safer_tab.c
    ${TOMCRYPT_FOLDER}/src/ciphers/skipjack.c
    ${TOMCRYPT_FOLDER}/src/ciphers/twofish/twofish.c
    ${TOMCRYPT_FOLDER}/src/ciphers/xtea.c
    ${TOMCRYPT_FOLDER}/src/encauth/ccm/ccm_memory.c
    ${TOMCRYPT_FOLDER}/src/encauth/ccm/ccm_test.c
    ${TOMCRYPT_FOLDER}/src/encauth/eax/eax_addheader.c
    ${TOMCRYPT_FOLDER}/src/encauth/eax/eax_decrypt.c
    ${TOMCRYPT_FOLDER}/src/encauth/eax/eax_decrypt_verify_memory.c
    ${TOMCRYPT_FOLDER}/src/encauth/eax/eax_done.c
    ${TOMCRYPT_FOLDER}/src/encauth/eax/eax_encrypt_authenticate_memory.c
    ${TOMCRYPT_FOLDER}/src/encauth/eax/eax_encrypt.c
    ${TOMCRYPT_FOLDER}/src/encauth/eax/eax_init.c
    ${TOMCRYPT_FOLDER}/src/encauth/eax/eax_test.c
    ${TOMCRYPT_FOLDER}/src/encauth/gcm/gcm_add_aad.c
    ${TOMCRYPT_FOLDER}/src/encauth/gcm/gcm_add_iv.c
    ${TOMCRYPT_FOLDER}/src/encauth/gcm/gcm_done.c
    ${TOMCRYPT_FOLDER}/src/encauth/gcm/gcm_gf_mult.c
    ${TOMCRYPT_FOLDER}/src/encauth/gcm/gcm_init.c
    ${TOMCRYPT_FOLDER}/src/encauth/gcm/gcm_memory.c
    ${TOMCRYPT_FOLDER}/src/encauth/gcm/gcm_mult_h.c
    ${TOMCRYPT_FOLDER}/src/encauth/gcm/gcm_process.c
    ${TOMCRYPT_FOLDER}/src/encauth/gcm/gcm_reset.c
    ${TOMCRYPT_FOLDER}/src/encauth/gcm/gcm_test.c
    ${TOMCRYPT_FOLDER}/src/encauth/ocb/ocb_decrypt.c
    ${TOMCRYPT_FOLDER}/src/encauth/ocb/ocb_decrypt_verify_memory.c
    ${TOMCRYPT_FOLDER}/src/encauth/ocb/ocb_done_decrypt.c
    ${TOMCRYPT_FOLDER}/src/encauth/ocb/ocb_done_encrypt.c
    ${TOMCRYPT_FOLDER}/src/encauth/ocb/ocb_encrypt_authenticate_memory.c
    ${TOMCRYPT_FOLDER}/src/encauth/ocb/ocb_encrypt.c
    ${TOMCRYPT_FOLDER}/src/encauth/ocb/ocb_init.c
    ${TOMCRYPT_FOLDER}/src/encauth/ocb/ocb_ntz.c
    ${TOMCRYPT_FOLDER}/src/encauth/ocb/ocb_shift_xor.c
    ${TOMCRYPT_FOLDER}/src/encauth/ocb/ocb_test.c
    ${TOMCRYPT_FOLDER}/src/encauth/ocb/s_ocb_done.c
    ${TOMCRYPT_FOLDER}/src/hashes/chc/chc.c
    ${TOMCRYPT_FOLDER}/src/hashes/helper/hash_file.c
    ${TOMCRYPT_FOLDER}/src/hashes/helper/hash_filehandle.c
    ${TOMCRYPT_FOLDER}/src/hashes/helper/hash_memory.c
    ${TOMCRYPT_FOLDER}/src/hashes/helper/hash_memory_multi.c
    ${TOMCRYPT_FOLDER}/src/hashes/md2.c
    ${TOMCRYPT_FOLDER}/src/hashes/md4.c
    ${TOMCRYPT_FOLDER}/src/hashes/md5.c
    ${TOMCRYPT_FOLDER}/src/hashes/rmd128.c
    ${TOMCRYPT_FOLDER}/src/hashes/rmd160.c
    ${TOMCRYPT_FOLDER}/src/hashes/rmd256.c
    ${TOMCRYPT_FOLDER}/src/hashes/rmd320.c
    ${TOMCRYPT_FOLDER}/src/hashes/sha1.c
    ${TOMCRYPT_FOLDER}/src/hashes/sha2/sha256.c
    ${TOMCRYPT_FOLDER}/src/hashes/sha2/sha512.c
    ${TOMCRYPT_FOLDER}/src/hashes/tiger.c
    ${TOMCRYPT_FOLDER}/src/hashes/whirl/whirl.c
    ${TOMCRYPT_FOLDER}/src/mac/f9/f9_done.c
    ${TOMCRYPT_FOLDER}/src/mac/f9/f9_file.c
    ${TOMCRYPT_FOLDER}/src/mac/f9/f9_init.c
    ${TOMCRYPT_FOLDER}/src/mac/f9/f9_memory.c
    ${TOMCRYPT_FOLDER}/src/mac/f9/f9_memory_multi.c
    ${TOMCRYPT_FOLDER}/src/mac/f9/f9_process.c
    ${TOMCRYPT_FOLDER}/src/mac/f9/f9_test.c
    ${TOMCRYPT_FOLDER}/src/mac/hmac/hmac_done.c
    ${TOMCRYPT_FOLDER}/src/mac/hmac/hmac_file.c
    ${TOMCRYPT_FOLDER}/src/mac/hmac/hmac_init.c
    ${TOMCRYPT_FOLDER}/src/mac/hmac/hmac_memory.c
    ${TOMCRYPT_FOLDER}/src/mac/hmac/hmac_memory_multi.c
    ${TOMCRYPT_FOLDER}/src/mac/hmac/hmac_process.c
    ${TOMCRYPT_FOLDER}/src/mac/hmac/hmac_test.c
    ${TOMCRYPT_FOLDER}/src/mac/omac/omac_done.c
    ${TOMCRYPT_FOLDER}/src/mac/omac/omac_file.c
    ${TOMCRYPT_FOLDER}/src/mac/omac/omac_init.c
    ${TOMCRYPT_FOLDER}/src/mac/omac/omac_memory.c
    ${TOMCRYPT_FOLDER}/src/mac/omac/omac_memory_multi.c
    ${TOMCRYPT_FOLDER}/src/mac/omac/omac_process.c
    ${TOMCRYPT_FOLDER}/src/mac/omac/omac_test.c
    ${TOMCRYPT_FOLDER}/src/mac/pelican/pelican.c
    ${TOMCRYPT_FOLDER}/src/mac/pelican/pelican_memory.c
    ${TOMCRYPT_FOLDER}/src/mac/pelican/pelican_test.c
    ${TOMCRYPT_FOLDER}/src/mac/pmac/pmac_done.c
    ${TOMCRYPT_FOLDER}/src/mac/pmac/pmac_file.c
    ${TOMCRYPT_FOLDER}/src/mac/pmac/pmac_init.c
    ${TOMCRYPT_FOLDER}/src/mac/pmac/pmac_memory.c
    ${TOMCRYPT_FOLDER}/src/mac/pmac/pmac_memory_multi.c
    ${TOMCRYPT_FOLDER}/src/mac/pmac/pmac_ntz.c
    ${TOMCRYPT_FOLDER}/src/mac/pmac/pmac_process.c
    ${TOMCRYPT_FOLDER}/src/mac/pmac/pmac_shift_xor.c
    ${TOMCRYPT_FOLDER}/src/mac/pmac/pmac_test.c
    ${TOMCRYPT_FOLDER}/src/mac/xcbc/xcbc_done.c
    ${TOMCRYPT_FOLDER}/src/mac/xcbc/xcbc_file.c
    ${TOMCRYPT_FOLDER}/src/mac/xcbc/xcbc_init.c
    ${TOMCRYPT_FOLDER}/src/mac/xcbc/xcbc_memory.c
    ${TOMCRYPT_FOLDER}/src/mac/xcbc/xcbc_memory_multi.c
    ${TOMCRYPT_FOLDER}/src/mac/xcbc/xcbc_process.c
    ${TOMCRYPT_FOLDER}/src/mac/xcbc/xcbc_test.c
    ${TOMCRYPT_FOLDER}/src/math/fp/ltc_ecc_fp_mulmod.c
    ${TOMCRYPT_FOLDER}/src/math/gmp_desc.c
    ${TOMCRYPT_FOLDER}/src/math/ltm_desc.c
    ${TOMCRYPT_FOLDER}/src/math/multi.c
    ${TOMCRYPT_FOLDER}/src/math/rand_prime.c
    ${TOMCRYPT_FOLDER}/src/math/tfm_desc.c
    ${TOMCRYPT_FOLDER}/src/misc/base64/base64_decode.c
    ${TOMCRYPT_FOLDER}/src/misc/base64/base64_encode.c
    ${TOMCRYPT_FOLDER}/src/misc/burn_stack.c
    ${TOMCRYPT_FOLDER}/src/misc/crypt/crypt_argchk.c
    ${TOMCRYPT_FOLDER}/src/misc/crypt/crypt.c
    ${TOMCRYPT_FOLDER}/src/misc/crypt/crypt_cipher_descriptor.c
    ${TOMCRYPT_FOLDER}/src/misc/crypt/crypt_cipher_is_valid.c
    ${TOMCRYPT_FOLDER}/src/misc/crypt/crypt_find_cipher_any.c
    ${TOMCRYPT_FOLDER}/src/misc/crypt/crypt_find_cipher.c
    ${TOMCRYPT_FOLDER}/src/misc/crypt/crypt_find_cipher_id.c
    ${TOMCRYPT_FOLDER}/src/misc/crypt/crypt_find_hash_any.c
    ${TOMCRYPT_FOLDER}/src/misc/crypt/crypt_find_hash.c
    ${TOMCRYPT_FOLDER}/src/misc/crypt/crypt_find_hash_id.c
    ${TOMCRYPT_FOLDER}/src/misc/crypt/crypt_find_hash_oid.c
    ${TOMCRYPT_FOLDER}/src/misc/crypt/crypt_find_prng.c
    ${TOMCRYPT_FOLDER}/src/misc/crypt/crypt_fsa.c
    ${TOMCRYPT_FOLDER}/src/misc/crypt/crypt_hash_descriptor.c
    ${TOMCRYPT_FOLDER}/src/misc/crypt/crypt_hash_is_valid.c
    ${TOMCRYPT_FOLDER}/src/misc/crypt/crypt_ltc_mp_descriptor.c
    ${TOMCRYPT_FOLDER}/src/misc/crypt/crypt_prng_descriptor.c
    ${TOMCRYPT_FOLDER}/src/misc/crypt/crypt_prng_is_valid.c
    ${TOMCRYPT_FOLDER}/src/misc/crypt/crypt_register_cipher.c
    ${TOMCRYPT_FOLDER}/src/misc/crypt/crypt_register_hash.c
    ${TOMCRYPT_FOLDER}/src/misc/crypt/crypt_register_prng.c
    ${TOMCRYPT_FOLDER}/src/misc/crypt/crypt_unregister_cipher.c
    ${TOMCRYPT_FOLDER}/src/misc/crypt/crypt_unregister_hash.c
    ${TOMCRYPT_FOLDER}/src/misc/crypt/crypt_unregister_prng.c
    ${TOMCRYPT_FOLDER}/src/misc/error_to_string.c
    ${TOMCRYPT_FOLDER}/src/misc/pkcs5/pkcs_5_1.c
    ${TOMCRYPT_FOLDER}/src/misc/pkcs5/pkcs_5_2.c
    ${TOMCRYPT_FOLDER}/src/misc/zeromem.c
    ${TOMCRYPT_FOLDER}/src/modes/cbc/cbc_decrypt.c
    ${TOMCRYPT_FOLDER}/src/modes/cbc/cbc_done.c
    ${TOMCRYPT_FOLDER}/src/modes/cbc/cbc_encrypt.c
    ${TOMCRYPT_FOLDER}/src/modes/cbc/cbc_getiv.c
    ${TOMCRYPT_FOLDER}/src/modes/cbc/cbc_setiv.c
    ${TOMCRYPT_FOLDER}/src/modes/cbc/cbc_start.c
    ${TOMCRYPT_FOLDER}/src/modes/cfb/cfb_decrypt.c
    ${TOMCRYPT_FOLDER}/src/modes/cfb/cfb_done.c
    ${TOMCRYPT_FOLDER}/src/modes/cfb/cfb_encrypt.c
    ${TOMCRYPT_FOLDER}/src/modes/cfb/cfb_getiv.c
    ${TOMCRYPT_FOLDER}/src/modes/cfb/cfb_setiv.c
    ${TOMCRYPT_FOLDER}/src/modes/cfb/cfb_start.c
    ${TOMCRYPT_FOLDER}/src/modes/ctr/ctr_decrypt.c
    ${TOMCRYPT_FOLDER}/src/modes/ctr/ctr_done.c
    ${TOMCRYPT_FOLDER}/src/modes/ctr/ctr_encrypt.c
    ${TOMCRYPT_FOLDER}/src/modes/ctr/ctr_getiv.c
    ${TOMCRYPT_FOLDER}/src/modes/ctr/ctr_setiv.c
    ${TOMCRYPT_FOLDER}/src/modes/ctr/ctr_start.c
    ${TOMCRYPT_FOLDER}/src/modes/ctr/ctr_test.c
    ${TOMCRYPT_FOLDER}/src/modes/ecb/ecb_decrypt.c
    ${TOMCRYPT_FOLDER}/src/modes/ecb/ecb_done.c
    ${TOMCRYPT_FOLDER}/src/modes/ecb/ecb_encrypt.c
    ${TOMCRYPT_FOLDER}/src/modes/ecb/ecb_start.c
    ${TOMCRYPT_FOLDER}/src/modes/f8/f8_decrypt.c
    ${TOMCRYPT_FOLDER}/src/modes/f8/f8_done.c
    ${TOMCRYPT_FOLDER}/src/modes/f8/f8_encrypt.c
    ${TOMCRYPT_FOLDER}/src/modes/f8/f8_getiv.c
    ${TOMCRYPT_FOLDER}/src/modes/f8/f8_setiv.c
    ${TOMCRYPT_FOLDER}/src/modes/f8/f8_start.c
    ${TOMCRYPT_FOLDER}/src/modes/f8/f8_test_mode.c
    ${TOMCRYPT_FOLDER}/src/modes/lrw/lrw_decrypt.c
    ${TOMCRYPT_FOLDER}/src/modes/lrw/lrw_done.c
    ${TOMCRYPT_FOLDER}/src/modes/lrw/lrw_encrypt.c
    ${TOMCRYPT_FOLDER}/src/modes/lrw/lrw_getiv.c
    ${TOMCRYPT_FOLDER}/src/modes/lrw/lrw_process.c
    ${TOMCRYPT_FOLDER}/src/modes/lrw/lrw_setiv.c
    ${TOMCRYPT_FOLDER}/src/modes/lrw/lrw_start.c
    ${TOMCRYPT_FOLDER}/src/modes/lrw/lrw_test.c
    ${TOMCRYPT_FOLDER}/src/modes/ofb/ofb_decrypt.c
    ${TOMCRYPT_FOLDER}/src/modes/ofb/ofb_done.c
    ${TOMCRYPT_FOLDER}/src/modes/ofb/ofb_encrypt.c
    ${TOMCRYPT_FOLDER}/src/modes/ofb/ofb_getiv.c
    ${TOMCRYPT_FOLDER}/src/modes/ofb/ofb_setiv.c
    ${TOMCRYPT_FOLDER}/src/modes/ofb/ofb_start.c
    ${TOMCRYPT_FOLDER}/src/modes/xts/xts_decrypt.c
    ${TOMCRYPT_FOLDER}/src/modes/xts/xts_done.c
    ${TOMCRYPT_FOLDER}/src/modes/xts/xts_encrypt.c
    ${TOMCRYPT_FOLDER}/src/modes/xts/xts_init.c
    ${TOMCRYPT_FOLDER}/src/modes/xts/xts_mult_x.c
    ${TOMCRYPT_FOLDER}/src/modes/xts/xts_test.c
    ${TOMCRYPT_FOLDER}/src/pk/asn1/der/bit/der_decode_bit_string.c
    ${TOMCRYPT_FOLDER}/src/pk/asn1/der/bit/der_encode_bit_string.c
    ${TOMCRYPT_FOLDER}/src/pk/asn1/der/bit/der_length_bit_string.c
    ${TOMCRYPT_FOLDER}/src/pk/asn1/der/boolean/der_decode_boolean.c
    ${TOMCRYPT_FOLDER}/src/pk/asn1/der/boolean/der_encode_boolean.c
    ${TOMCRYPT_FOLDER}/src/pk/asn1/der/boolean/der_length_boolean.c
    ${TOMCRYPT_FOLDER}/src/pk/asn1/der/choice/der_decode_choice.c
    ${TOMCRYPT_FOLDER}/src/pk/asn1/der/ia5/der_decode_ia5_string.c
    ${TOMCRYPT_FOLDER}/src/pk/asn1/der/ia5/der_encode_ia5_string.c
    ${TOMCRYPT_FOLDER}/src/pk/asn1/der/ia5/der_length_ia5_string.c
    ${TOMCRYPT_FOLDER}/src/pk/asn1/der/integer/der_decode_integer.c
    ${TOMCRYPT_FOLDER}/src/pk/asn1/der/integer/der_encode_integer.c
    ${TOMCRYPT_FOLDER}/src/pk/asn1/der/integer/der_length_integer.c
    ${TOMCRYPT_FOLDER}/src/pk/asn1/der/object_identifier/der_decode_object_identifier.c
    ${TOMCRYPT_FOLDER}/src/pk/asn1/der/object_identifier/der_encode_object_identifier.c
    ${TOMCRYPT_FOLDER}/src/pk/asn1/der/object_identifier/der_length_object_identifier.c
    ${TOMCRYPT_FOLDER}/src/pk/asn1/der/octet/der_decode_octet_string.c
    ${TOMCRYPT_FOLDER}/src/pk/asn1/der/octet/der_encode_octet_string.c
    ${TOMCRYPT_FOLDER}/src/pk/asn1/der/octet/der_length_octet_string.c
    ${TOMCRYPT_FOLDER}/src/pk/asn1/der/printable_string/der_decode_printable_string.c
    ${TOMCRYPT_FOLDER}/src/pk/asn1/der/printable_string/der_encode_printable_string.c
    ${TOMCRYPT_FOLDER}/src/pk/asn1/der/printable_string/der_length_printable_string.c
    ${TOMCRYPT_FOLDER}/src/pk/asn1/der/sequence/der_decode_sequence_ex.c
    ${TOMCRYPT_FOLDER}/src/pk/asn1/der/sequence/der_decode_sequence_flexi.c
    ${TOMCRYPT_FOLDER}/src/pk/asn1/der/sequence/der_decode_sequence_multi.c
    ${TOMCRYPT_FOLDER}/src/pk/asn1/der/sequence/der_encode_sequence_ex.c
    ${TOMCRYPT_FOLDER}/src/pk/asn1/der/sequence/der_encode_sequence_multi.c
    ${TOMCRYPT_FOLDER}/src/pk/asn1/der/sequence/der_length_sequence.c
    ${TOMCRYPT_FOLDER}/src/pk/asn1/der/sequence/der_sequence_free.c
    ${TOMCRYPT_FOLDER}/src/pk/asn1/der/set/der_encode_set.c
    ${TOMCRYPT_FOLDER}/src/pk/asn1/der/set/der_encode_setof.c
    ${TOMCRYPT_FOLDER}/src/pk/asn1/der/short_integer/der_decode_short_integer.c
    ${TOMCRYPT_FOLDER}/src/pk/asn1/der/short_integer/der_encode_short_integer.c
    ${TOMCRYPT_FOLDER}/src/pk/asn1/der/short_integer/der_length_short_integer.c
    ${TOMCRYPT_FOLDER}/src/pk/asn1/der/utctime/der_decode_utctime.c
    ${TOMCRYPT_FOLDER}/src/pk/asn1/der/utctime/der_encode_utctime.c
    ${TOMCRYPT_FOLDER}/src/pk/asn1/der/utctime/der_length_utctime.c
    ${TOMCRYPT_FOLDER}/src/pk/asn1/der/utf8/der_decode_utf8_string.c
    ${TOMCRYPT_FOLDER}/src/pk/asn1/der/utf8/der_encode_utf8_string.c
    ${TOMCRYPT_FOLDER}/src/pk/asn1/der/utf8/der_length_utf8_string.c
    ${TOMCRYPT_FOLDER}/src/pk/dsa/dsa_decrypt_key.c
    ${TOMCRYPT_FOLDER}/src/pk/dsa/dsa_encrypt_key.c
    ${TOMCRYPT_FOLDER}/src/pk/dsa/dsa_export.c
    ${TOMCRYPT_FOLDER}/src/pk/dsa/dsa_free.c
    ${TOMCRYPT_FOLDER}/src/pk/dsa/dsa_import.c
    ${TOMCRYPT_FOLDER}/src/pk/dsa/dsa_make_key.c
    ${TOMCRYPT_FOLDER}/src/pk/dsa/dsa_shared_secret.c
    ${TOMCRYPT_FOLDER}/src/pk/dsa/dsa_sign_hash.c
    ${TOMCRYPT_FOLDER}/src/pk/dsa/dsa_verify_hash.c
    ${TOMCRYPT_FOLDER}/src/pk/dsa/dsa_verify_key.c
    ${TOMCRYPT_FOLDER}/src/pk/ecc/ecc_ansi_x963_export.c
    ${TOMCRYPT_FOLDER}/src/pk/ecc/ecc_ansi_x963_import.c
    ${TOMCRYPT_FOLDER}/src/pk/ecc/ecc.c
    ${TOMCRYPT_FOLDER}/src/pk/ecc/ecc_decrypt_key.c
    ${TOMCRYPT_FOLDER}/src/pk/ecc/ecc_encrypt_key.c
    ${TOMCRYPT_FOLDER}/src/pk/ecc/ecc_export.c
    ${TOMCRYPT_FOLDER}/src/pk/ecc/ecc_free.c
    ${TOMCRYPT_FOLDER}/src/pk/ecc/ecc_get_size.c
    ${TOMCRYPT_FOLDER}/src/pk/ecc/ecc_import.c
    ${TOMCRYPT_FOLDER}/src/pk/ecc/ecc_make_key.c
    ${TOMCRYPT_FOLDER}/src/pk/ecc/ecc_shared_secret.c
    ${TOMCRYPT_FOLDER}/src/pk/ecc/ecc_sign_hash.c
    ${TOMCRYPT_FOLDER}/src/pk/ecc/ecc_sizes.c
    ${TOMCRYPT_FOLDER}/src/pk/ecc/ecc_test.c
    ${TOMCRYPT_FOLDER}/src/pk/ecc/ecc_verify_hash.c
    ${TOMCRYPT_FOLDER}/src/pk/ecc/ltc_ecc_is_valid_idx.c
    ${TOMCRYPT_FOLDER}/src/pk/ecc/ltc_ecc_map.c
    ${TOMCRYPT_FOLDER}/src/pk/ecc/ltc_ecc_mul2add.c
    ${TOMCRYPT_FOLDER}/src/pk/ecc/ltc_ecc_mulmod.c
    ${TOMCRYPT_FOLDER}/src/pk/ecc/ltc_ecc_mulmod_timing.c
    ${TOMCRYPT_FOLDER}/src/pk/ecc/ltc_ecc_points.c
    ${TOMCRYPT_FOLDER}/src/pk/ecc/ltc_ecc_projective_add_point.c
    ${TOMCRYPT_FOLDER}/src/pk/ecc/ltc_ecc_projective_dbl_point.c
    ${TOMCRYPT_FOLDER}/src/pk/katja/katja_decrypt_key.c
    ${TOMCRYPT_FOLDER}/src/pk/katja/katja_encrypt_key.c
    ${TOMCRYPT_FOLDER}/src/pk/katja/katja_export.c
    ${TOMCRYPT_FOLDER}/src/pk/katja/katja_exptmod.c
    ${TOMCRYPT_FOLDER}/src/pk/katja/katja_free.c
    ${TOMCRYPT_FOLDER}/src/pk/katja/katja_import.c
    ${TOMCRYPT_FOLDER}/src/pk/katja/katja_make_key.c
    ${TOMCRYPT_FOLDER}/src/pk/pkcs1/pkcs_1_i2osp.c
    ${TOMCRYPT_FOLDER}/src/pk/pkcs1/pkcs_1_mgf1.c
    ${TOMCRYPT_FOLDER}/src/pk/pkcs1/pkcs_1_oaep_decode.c
    ${TOMCRYPT_FOLDER}/src/pk/pkcs1/pkcs_1_oaep_encode.c
    ${TOMCRYPT_FOLDER}/src/pk/pkcs1/pkcs_1_os2ip.c
    ${TOMCRYPT_FOLDER}/src/pk/pkcs1/pkcs_1_pss_decode.c
    ${TOMCRYPT_FOLDER}/src/pk/pkcs1/pkcs_1_pss_encode.c
    ${TOMCRYPT_FOLDER}/src/pk/pkcs1/pkcs_1_v1_5_decode.c
    ${TOMCRYPT_FOLDER}/src/pk/pkcs1/pkcs_1_v1_5_encode.c
    ${TOMCRYPT_FOLDER}/src/pk/rsa/rsa_decrypt_key.c
    ${TOMCRYPT_FOLDER}/src/pk/rsa/rsa_encrypt_key.c
    ${TOMCRYPT_FOLDER}/src/pk/rsa/rsa_export.c
    ${TOMCRYPT_FOLDER}/src/pk/rsa/rsa_exptmod.c
    ${TOMCRYPT_FOLDER}/src/pk/rsa/rsa_free.c
    ${TOMCRYPT_FOLDER}/src/pk/rsa/rsa_import.c
    ${TOMCRYPT_FOLDER}/src/pk/rsa/rsa_make_key.c
    ${TOMCRYPT_FOLDER}/src/pk/rsa/rsa_sign_hash.c
    ${TOMCRYPT_FOLDER}/src/pk/rsa/rsa_verify_hash.c
    ${TOMCRYPT_FOLDER}/src/prngs/fortuna.c
    ${TOMCRYPT_FOLDER}/src/prngs/rc4.c
    ${TOMCRYPT_FOLDER}/src/prngs/rng_get_bytes.c
    ${TOMCRYPT_FOLDER}/src/prngs/rng_make_prng.c
    ${TOMCRYPT_FOLDER}/src/prngs/sober128.c
    ${TOMCRYPT_FOLDER}/src/prngs/sprng.c
    ${TOMCRYPT_FOLDER}/src/prngs/yarrow.c)

set(TOMCRYPT_PUBLIC_HEADERS
    ${TOMCRYPT_FOLDER}/src/headers/tomcrypt_cfg.h
    ${TOMCRYPT_FOLDER}/src/headers/tomcrypt_mac.h
    ${TOMCRYPT_FOLDER}/src/headers/tomcrypt_argchk.h
    ${TOMCRYPT_FOLDER}/src/headers/tomcrypt_cipher.h
    ${TOMCRYPT_FOLDER}/src/headers/tomcrypt_custom.h
    ${TOMCRYPT_FOLDER}/src/headers/tomcrypt_hash.h
    ${TOMCRYPT_FOLDER}/src/headers/tomcrypt_macros.h
    ${TOMCRYPT_FOLDER}/src/headers/tomcrypt_math.h
    ${TOMCRYPT_FOLDER}/src/headers/tomcrypt_pk.h
    ${TOMCRYPT_FOLDER}/src/headers/tomcrypt_misc.h
    ${TOMCRYPT_FOLDER}/src/headers/tomcrypt.h
    ${TOMCRYPT_FOLDER}/src/headers/tomcrypt_pkcs.h
    ${TOMCRYPT_FOLDER}/src/headers/tomcrypt_prng.h
)

# set(TOMCRYPT_PRIVATE_HEADERS src/headers/tomcrypt_private.h)
set_property(GLOBAL PROPERTY PUBLIC_HEADERS ${TOMCRYPT_PUBLIC_HEADERS})

