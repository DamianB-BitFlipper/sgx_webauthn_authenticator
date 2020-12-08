#include "Enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


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

static sgx_status_t SGX_CDECL sgx_get_public_keys(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_get_public_keys_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_get_public_keys_t* ms = SGX_CAST(ms_get_public_keys_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_ec256_public_t* _tmp_ret_ec256_pk = ms->ms_ret_ec256_pk;
	size_t _len_ret_ec256_pk = sizeof(sgx_ec256_public_t);
	sgx_ec256_public_t* _in_ret_ec256_pk = NULL;
	uint8_t* _tmp_ret_n = ms->ms_ret_n;
	size_t _len_ret_n = 256 * sizeof(uint8_t);
	uint8_t* _in_ret_n = NULL;
	uint8_t* _tmp_ret_e = ms->ms_ret_e;
	size_t _len_ret_e = 2 * sizeof(uint8_t);
	uint8_t* _in_ret_e = NULL;

	if (sizeof(*_tmp_ret_n) != 0 &&
		256 > (SIZE_MAX / sizeof(*_tmp_ret_n))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	if (sizeof(*_tmp_ret_e) != 0 &&
		2 > (SIZE_MAX / sizeof(*_tmp_ret_e))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	CHECK_UNIQUE_POINTER(_tmp_ret_ec256_pk, _len_ret_ec256_pk);
	CHECK_UNIQUE_POINTER(_tmp_ret_n, _len_ret_n);
	CHECK_UNIQUE_POINTER(_tmp_ret_e, _len_ret_e);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_ret_ec256_pk != NULL && _len_ret_ec256_pk != 0) {
		if ((_in_ret_ec256_pk = (sgx_ec256_public_t*)malloc(_len_ret_ec256_pk)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_ret_ec256_pk, 0, _len_ret_ec256_pk);
	}
	if (_tmp_ret_n != NULL && _len_ret_n != 0) {
		if ( _len_ret_n % sizeof(*_tmp_ret_n) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_ret_n = (uint8_t*)malloc(_len_ret_n)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_ret_n, 0, _len_ret_n);
	}
	if (_tmp_ret_e != NULL && _len_ret_e != 0) {
		if ( _len_ret_e % sizeof(*_tmp_ret_e) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_ret_e = (uint8_t*)malloc(_len_ret_e)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_ret_e, 0, _len_ret_e);
	}

	ms->ms_retval = get_public_keys(_in_ret_ec256_pk, _in_ret_n, _in_ret_e);
	if (_in_ret_ec256_pk) {
		if (memcpy_s(_tmp_ret_ec256_pk, _len_ret_ec256_pk, _in_ret_ec256_pk, _len_ret_ec256_pk)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_ret_n) {
		if (memcpy_s(_tmp_ret_n, _len_ret_n, _in_ret_n, _len_ret_n)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_ret_e) {
		if (memcpy_s(_tmp_ret_e, _len_ret_e, _in_ret_e, _len_ret_e)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_ret_ec256_pk) free(_in_ret_ec256_pk);
	if (_in_ret_n) free(_in_ret_n);
	if (_in_ret_e) free(_in_ret_e);
	return status;
}

static sgx_status_t SGX_CDECL sgx_sign_data(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_sign_data_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_sign_data_t* ms = SGX_CAST(ms_sign_data_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const uint8_t* _tmp_data = ms->ms_data;
	uint32_t _tmp_data_size = ms->ms_data_size;
	size_t _len_data = _tmp_data_size * sizeof(uint8_t);
	uint8_t* _in_data = NULL;
	sgx_ec256_signature_t* _tmp_ret_signature = ms->ms_ret_signature;
	size_t _len_ret_signature = sizeof(sgx_ec256_signature_t);
	sgx_ec256_signature_t* _in_ret_signature = NULL;

	if (sizeof(*_tmp_data) != 0 &&
		(size_t)_tmp_data_size > (SIZE_MAX / sizeof(*_tmp_data))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	CHECK_UNIQUE_POINTER(_tmp_data, _len_data);
	CHECK_UNIQUE_POINTER(_tmp_ret_signature, _len_ret_signature);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_data != NULL && _len_data != 0) {
		if ( _len_data % sizeof(*_tmp_data) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_data = (uint8_t*)malloc(_len_data);
		if (_in_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_data, _len_data, _tmp_data, _len_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_ret_signature != NULL && _len_ret_signature != 0) {
		if ((_in_ret_signature = (sgx_ec256_signature_t*)malloc(_len_ret_signature)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_ret_signature, 0, _len_ret_signature);
	}

	ms->ms_retval = sign_data((const uint8_t*)_in_data, _tmp_data_size, _in_ret_signature);
	if (_in_ret_signature) {
		if (memcpy_s(_tmp_ret_signature, _len_ret_signature, _in_ret_signature, _len_ret_signature)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_data) free(_in_data);
	if (_in_ret_signature) free(_in_ret_signature);
	return status;
}

static sgx_status_t SGX_CDECL sgx_webauthn_get_signature(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_webauthn_get_signature_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_webauthn_get_signature_t* ms = SGX_CAST(ms_webauthn_get_signature_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const uint8_t* _tmp_data = ms->ms_data;
	uint32_t _tmp_data_size = ms->ms_data_size;
	size_t _len_data = _tmp_data_size * sizeof(uint8_t);
	uint8_t* _in_data = NULL;
	const uint8_t* _tmp_client_data = ms->ms_client_data;
	uint32_t _tmp_client_data_size = ms->ms_client_data_size;
	size_t _len_client_data = _tmp_client_data_size * sizeof(uint8_t);
	uint8_t* _in_client_data = NULL;
	sgx_ec256_signature_t* _tmp_ret_signature = ms->ms_ret_signature;
	size_t _len_ret_signature = sizeof(sgx_ec256_signature_t);
	sgx_ec256_signature_t* _in_ret_signature = NULL;

	if (sizeof(*_tmp_data) != 0 &&
		(size_t)_tmp_data_size > (SIZE_MAX / sizeof(*_tmp_data))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	if (sizeof(*_tmp_client_data) != 0 &&
		(size_t)_tmp_client_data_size > (SIZE_MAX / sizeof(*_tmp_client_data))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	CHECK_UNIQUE_POINTER(_tmp_data, _len_data);
	CHECK_UNIQUE_POINTER(_tmp_client_data, _len_client_data);
	CHECK_UNIQUE_POINTER(_tmp_ret_signature, _len_ret_signature);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_data != NULL && _len_data != 0) {
		if ( _len_data % sizeof(*_tmp_data) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_data = (uint8_t*)malloc(_len_data);
		if (_in_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_data, _len_data, _tmp_data, _len_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_client_data != NULL && _len_client_data != 0) {
		if ( _len_client_data % sizeof(*_tmp_client_data) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_client_data = (uint8_t*)malloc(_len_client_data);
		if (_in_client_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_client_data, _len_client_data, _tmp_client_data, _len_client_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_ret_signature != NULL && _len_ret_signature != 0) {
		if ((_in_ret_signature = (sgx_ec256_signature_t*)malloc(_len_ret_signature)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_ret_signature, 0, _len_ret_signature);
	}

	ms->ms_retval = webauthn_get_signature((const uint8_t*)_in_data, _tmp_data_size, (const uint8_t*)_in_client_data, _tmp_client_data_size, _in_ret_signature);
	if (_in_ret_signature) {
		if (memcpy_s(_tmp_ret_signature, _len_ret_signature, _in_ret_signature, _len_ret_signature)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_data) free(_in_data);
	if (_in_client_data) free(_in_client_data);
	if (_in_ret_signature) free(_in_ret_signature);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[3];
} g_ecall_table = {
	3,
	{
		{(void*)(uintptr_t)sgx_get_public_keys, 0, 0},
		{(void*)(uintptr_t)sgx_sign_data, 0, 0},
		{(void*)(uintptr_t)sgx_webauthn_get_signature, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[3][3];
} g_dyn_entry_table = {
	3,
	{
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL untrusted_print_string(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_untrusted_print_string_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_untrusted_print_string_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_untrusted_print_string_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_untrusted_print_string_t));
	ocalloc_size -= sizeof(ms_untrusted_print_string_t);

	if (str != NULL) {
		ms->ms_str = (const char*)__tmp;
		if (_len_str % sizeof(*str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}
	
	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL untrusted_save_enclave_data(int32_t* retval, const char* data_file, const uint8_t* sealed_data, size_t sealed_size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_data_file = 64 * sizeof(char);
	size_t _len_sealed_data = sealed_size * sizeof(uint8_t);

	ms_untrusted_save_enclave_data_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_untrusted_save_enclave_data_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(data_file, _len_data_file);
	CHECK_ENCLAVE_POINTER(sealed_data, _len_sealed_data);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (data_file != NULL) ? _len_data_file : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (sealed_data != NULL) ? _len_sealed_data : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_untrusted_save_enclave_data_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_untrusted_save_enclave_data_t));
	ocalloc_size -= sizeof(ms_untrusted_save_enclave_data_t);

	if (data_file != NULL) {
		ms->ms_data_file = (const char*)__tmp;
		if (_len_data_file % sizeof(*data_file) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, data_file, _len_data_file)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_data_file);
		ocalloc_size -= _len_data_file;
	} else {
		ms->ms_data_file = NULL;
	}
	
	if (sealed_data != NULL) {
		ms->ms_sealed_data = (const uint8_t*)__tmp;
		if (_len_sealed_data % sizeof(*sealed_data) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, sealed_data, _len_sealed_data)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_sealed_data);
		ocalloc_size -= _len_sealed_data;
	} else {
		ms->ms_sealed_data = NULL;
	}
	
	ms->ms_sealed_size = sealed_size;
	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL untrusted_load_enclave_data(int32_t* retval, const char* data_file, uint8_t* sealed_data, size_t sealed_size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_data_file = 64 * sizeof(char);
	size_t _len_sealed_data = sealed_size * sizeof(uint8_t);

	ms_untrusted_load_enclave_data_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_untrusted_load_enclave_data_t);
	void *__tmp = NULL;

	void *__tmp_sealed_data = NULL;

	CHECK_ENCLAVE_POINTER(data_file, _len_data_file);
	CHECK_ENCLAVE_POINTER(sealed_data, _len_sealed_data);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (data_file != NULL) ? _len_data_file : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (sealed_data != NULL) ? _len_sealed_data : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_untrusted_load_enclave_data_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_untrusted_load_enclave_data_t));
	ocalloc_size -= sizeof(ms_untrusted_load_enclave_data_t);

	if (data_file != NULL) {
		ms->ms_data_file = (const char*)__tmp;
		if (_len_data_file % sizeof(*data_file) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, data_file, _len_data_file)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_data_file);
		ocalloc_size -= _len_data_file;
	} else {
		ms->ms_data_file = NULL;
	}
	
	if (sealed_data != NULL) {
		ms->ms_sealed_data = (uint8_t*)__tmp;
		__tmp_sealed_data = __tmp;
		if (_len_sealed_data % sizeof(*sealed_data) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_sealed_data, 0, _len_sealed_data);
		__tmp = (void *)((size_t)__tmp + _len_sealed_data);
		ocalloc_size -= _len_sealed_data;
	} else {
		ms->ms_sealed_data = NULL;
	}
	
	ms->ms_sealed_size = sealed_size;
	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (sealed_data) {
			if (memcpy_s((void*)sealed_data, _len_sealed_data, __tmp_sealed_data, _len_sealed_data)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

