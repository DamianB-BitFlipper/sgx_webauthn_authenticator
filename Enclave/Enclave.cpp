/*
 * Copyright (C) 2011-2018 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>      /* vsnprintf */
#include <string.h>

#include "Enclave.h"
#include "Enclave_t.h"  /* print_string */

#include "sgx_trts.h"
#include "sgx_tcrypto.h"
#include "sgx_tseal.h"

typedef struct {
  sgx_ec256_public_t pk;
  sgx_ec256_private_t sk;
} ec256_pk_sk_pair;

// Function Declarations
static sgx_status_t get_pk_sk_pair(ec256_pk_sk_pair *pk_sk_pair);

/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
void printf(const char *fmt, ...) {
  char buf[BUFSIZ] = {'\0'};
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(buf, BUFSIZ, fmt, ap);
  va_end(ap);
  untrusted_print_string(buf);
}

sgx_status_t get_public_key(sgx_ec256_public_t *ret_pk) {
  ec256_pk_sk_pair pk_sk_pair;
  sgx_status_t status = get_pk_sk_pair(&pk_sk_pair);

  // No errors, copy the public key over
  if (!status) {
    *ret_pk = pk_sk_pair.pk;
  }

  return status;
}

// TODO: All of these frees can be cleaned up. Split
// the case where a new key needs to be created
// into a helper function, and so forth
static sgx_status_t get_pk_sk_pair(ec256_pk_sk_pair *pk_sk_pair) {
  sgx_status_t status;

  const size_t pk_sk_pair_size = sizeof(*pk_sk_pair);

  int32_t error;
  size_t sealed_size = sgx_calc_sealed_data_size(0, pk_sk_pair_size);
  uint8_t *sealed_data = (uint8_t*)malloc(sealed_size);

  untrusted_load_enclave_data(&error, sealed_data, sealed_size);

  // Private key does not exist, create one and save it!
  if (error) {
    sgx_ecc_state_handle_t handle;

    status = sgx_ecc256_open_context(&handle);
    if (status) {
      sgx_ecc256_close_context(handle);
      free(sealed_data);
      return status;
    }

    status = sgx_ecc256_create_key_pair(&pk_sk_pair->sk, &pk_sk_pair->pk, handle);
    if (status) {
      sgx_ecc256_close_context(handle);
      free(sealed_data);
      return status;
    }

    // Seal the new public/private keys
    status = sgx_seal_data(0, NULL, pk_sk_pair_size, (const uint8_t*)pk_sk_pair, 
                           sealed_size,  (sgx_sealed_data_t*)sealed_data);

    if (status) {
      sgx_ecc256_close_context(handle);
      free(sealed_data);
      return status;
    }

    // Write back the sealed_data
    untrusted_save_enclave_data(&error, sealed_data, sealed_size);

    if (error) {
      status = SGX_ERROR_UNEXPECTED;
    } else {
      status = SGX_SUCCESS;
    }

    sgx_ecc256_close_context(handle);
    free(sealed_data);
    return status;
  }

  // Load the public/private keys from the sealed_data
  status = sgx_unseal_data((sgx_sealed_data_t*)sealed_data, NULL, NULL, (uint8_t*)pk_sk_pair, (uint32_t*)&pk_sk_pair_size);

  if (status) {
    free(sealed_data);
    return status;
  }  

  free(sealed_data);
  return status;
}

sgx_status_t sign_data(const uint8_t *data, uint32_t data_size, sgx_ec256_signature_t *ret_signature) {
  sgx_status_t status;

  // Open up a ECC state context
  sgx_ecc_state_handle_t handle;
  status = sgx_ecc256_open_context(&handle);  

  if (status) {
    sgx_ecc256_close_context(handle);
    return status;
  }

  // Get the private key from the enclave
  ec256_pk_sk_pair pk_sk_pair;
  status = get_pk_sk_pair(&pk_sk_pair);

  if (status) {
    sgx_ecc256_close_context(handle);
    return status;
  }

  // Compute the signature locally
  sgx_ec256_signature_t signature;
  status = sgx_ecdsa_sign(data, data_size, &pk_sk_pair.sk, &signature, handle);

  if (status) {
    sgx_ecc256_close_context(handle);
    return status;
  }

  // Successfully signed, copy the signature over
  *ret_signature = signature;

  sgx_ecc256_close_context(handle);
  return status;
}

// Compute the signature of a given piece of `data` according 
// to the webauthn specification and input `client_data_json`
sgx_status_t webauthn_get_signature(const uint8_t *data, uint32_t data_size,
                                    const uint8_t *client_data_json, uint32_t client_data_json_size,
                                    sgx_ec256_signature_t *ret_signature) {
  // Expected `data_size` for the signature is 69 bytes
  // (two hashes x 32 bytes + 5 bytes metadata)
  if (data_size != 69) {
    return SGX_ERROR_UNEXPECTED;
  }

  // TODO: Perform SHA256 on `client_data_json` and compare with 2nd half of `data`

  // TODO: This is hacky and bug-prone
  //
  // Search the client data to see if this a txAuthSimple event
  // Look for the string `"clientExtensions":{"txAuthSimple":` to get the transaction text
  const char *txAuthSimple_search_text = "\"clientExtensions\":{\"txAuthSimple\":";
  char *auth_text_start = strstr((const char*)client_data_json, txAuthSimple_search_text);
  
  // This must be a regular authentication event, simply sign
  if (auth_text_start == NULL) {
    return sign_data(data, data_size, ret_signature);
  }

  // Skip forward the search text in the authentication text start
  auth_text_start += strlen(txAuthSimple_search_text);

  // Look for the end of the authentication text
  char *auth_text_end = strstr(auth_text_start, "}");

  // Expect a closing bracket
  if (auth_text_end == NULL) {
    return SGX_ERROR_UNEXPECTED;
  }

  // Mark the end of the authentication text before printing it
  *auth_text_end = 0;

  printf("Authentication text: %s\n", auth_text_start);

  // TODO: Ask for user input

  return sign_data(data, data_size, ret_signature);
}
