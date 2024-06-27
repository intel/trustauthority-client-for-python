/*
 * Copyright (C) 2023 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _UTILS_H_
#define _UTILS_H_

#if defined(__cplusplus)
extern "C" {
#endif

int get_public_key(sgx_enclave_id_t eid, uint8_t **pp_key, uint32_t *p_key_size);
void free_public_key(uint8_t *p_key);

#if defined(__cplusplus)
}
#endif

#endif /*_UTILS_H_*/

