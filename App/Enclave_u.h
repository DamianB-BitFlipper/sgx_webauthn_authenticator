#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

#include "sgx_tcrypto.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef UNTRUSTED_PRINT_STRING_DEFINED__
#define UNTRUSTED_PRINT_STRING_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, untrusted_print_string, (const char* str));
#endif
#ifndef UNTRUSTED_SAVE_ENCLAVE_DATA_DEFINED__
#define UNTRUSTED_SAVE_ENCLAVE_DATA_DEFINED__
int32_t SGX_UBRIDGE(SGX_NOCONVENTION, untrusted_save_enclave_data, (const uint8_t* sealed_data, size_t sealed_size));
#endif
#ifndef UNTRUSTED_LOAD_ENCLAVE_DATA_DEFINED__
#define UNTRUSTED_LOAD_ENCLAVE_DATA_DEFINED__
int32_t SGX_UBRIDGE(SGX_NOCONVENTION, untrusted_load_enclave_data, (uint8_t* sealed_data, size_t sealed_size));
#endif

sgx_status_t get_public_key(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ec256_public_t* ret_pk);
sgx_status_t sign_data(sgx_enclave_id_t eid, sgx_status_t* retval, const uint8_t* data, uint32_t data_size, sgx_ec256_signature_t* ret_signature);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
