#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_get_public_keys_t {
	sgx_status_t ms_retval;
	sgx_ec256_public_t* ms_ret_ec256_pk;
	uint8_t* ms_ret_n;
	uint8_t* ms_ret_e;
} ms_get_public_keys_t;

typedef struct ms_sign_data_t {
	sgx_status_t ms_retval;
	const uint8_t* ms_data;
	uint32_t ms_data_size;
	sgx_ec256_signature_t* ms_ret_signature;
} ms_sign_data_t;

typedef struct ms_webauthn_get_signature_t {
	sgx_status_t ms_retval;
	const uint8_t* ms_data;
	uint32_t ms_data_size;
	const uint8_t* ms_client_data;
	uint32_t ms_client_data_size;
	sgx_ec256_signature_t* ms_ret_signature;
} ms_webauthn_get_signature_t;

typedef struct ms_untrusted_print_string_t {
	const char* ms_str;
} ms_untrusted_print_string_t;

typedef struct ms_untrusted_save_enclave_data_t {
	int32_t ms_retval;
	const char* ms_data_file;
	const uint8_t* ms_sealed_data;
	size_t ms_sealed_size;
} ms_untrusted_save_enclave_data_t;

typedef struct ms_untrusted_load_enclave_data_t {
	int32_t ms_retval;
	const char* ms_data_file;
	uint8_t* ms_sealed_data;
	size_t ms_sealed_size;
} ms_untrusted_load_enclave_data_t;

static sgx_status_t SGX_CDECL Enclave_untrusted_print_string(void* pms)
{
	ms_untrusted_print_string_t* ms = SGX_CAST(ms_untrusted_print_string_t*, pms);
	untrusted_print_string(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_untrusted_save_enclave_data(void* pms)
{
	ms_untrusted_save_enclave_data_t* ms = SGX_CAST(ms_untrusted_save_enclave_data_t*, pms);
	ms->ms_retval = untrusted_save_enclave_data(ms->ms_data_file, ms->ms_sealed_data, ms->ms_sealed_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_untrusted_load_enclave_data(void* pms)
{
	ms_untrusted_load_enclave_data_t* ms = SGX_CAST(ms_untrusted_load_enclave_data_t*, pms);
	ms->ms_retval = untrusted_load_enclave_data(ms->ms_data_file, ms->ms_sealed_data, ms->ms_sealed_size);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[3];
} ocall_table_Enclave = {
	3,
	{
		(void*)Enclave_untrusted_print_string,
		(void*)Enclave_untrusted_save_enclave_data,
		(void*)Enclave_untrusted_load_enclave_data,
	}
};
sgx_status_t get_public_keys(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ec256_public_t* ret_ec256_pk, uint8_t* ret_n, uint8_t* ret_e)
{
	sgx_status_t status;
	ms_get_public_keys_t ms;
	ms.ms_ret_ec256_pk = ret_ec256_pk;
	ms.ms_ret_n = ret_n;
	ms.ms_ret_e = ret_e;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sign_data(sgx_enclave_id_t eid, sgx_status_t* retval, const uint8_t* data, uint32_t data_size, sgx_ec256_signature_t* ret_signature)
{
	sgx_status_t status;
	ms_sign_data_t ms;
	ms.ms_data = data;
	ms.ms_data_size = data_size;
	ms.ms_ret_signature = ret_signature;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t webauthn_get_signature(sgx_enclave_id_t eid, sgx_status_t* retval, const uint8_t* data, uint32_t data_size, const uint8_t* client_data, uint32_t client_data_size, sgx_ec256_signature_t* ret_signature)
{
	sgx_status_t status;
	ms_webauthn_get_signature_t ms;
	ms.ms_data = data;
	ms.ms_data_size = data_size;
	ms.ms_client_data = client_data;
	ms.ms_client_data_size = client_data_size;
	ms.ms_ret_signature = ret_signature;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

