#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "sgx_tcrypto.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

sgx_status_t get_public_key(sgx_ec256_public_t* ret_pk);
sgx_status_t sign_data(const uint8_t* data, uint32_t data_size, sgx_ec256_signature_t* ret_signature);

sgx_status_t SGX_CDECL untrusted_print_string(const char* str);
sgx_status_t SGX_CDECL untrusted_save_enclave_data(int32_t* retval, const uint8_t* sealed_data, size_t sealed_size);
sgx_status_t SGX_CDECL untrusted_load_enclave_data(int32_t* retval, uint8_t* sealed_data, size_t sealed_size);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
