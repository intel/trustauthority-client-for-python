#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_enclave_create_pubkey_t {
	sgx_status_t ms_retval;
	rsa_params_t* ms_key;
} ms_enclave_create_pubkey_t;

typedef struct ms_enclave_create_report_t {
	uint32_t ms_retval;
	const sgx_target_info_t* ms_p_qe3_target;
	uint8_t* ms_nonce;
	uint32_t ms_nonce_size;
	sgx_report_t* ms_p_report;
} ms_enclave_create_report_t;

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_Enclave = {
	0,
	{ NULL },
};
sgx_status_t enclave_create_pubkey(sgx_enclave_id_t eid, sgx_status_t* retval, rsa_params_t* key)
{
	sgx_status_t status;
	ms_enclave_create_pubkey_t ms;
	ms.ms_key = key;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enclave_create_report(sgx_enclave_id_t eid, uint32_t* retval, const sgx_target_info_t* p_qe3_target, uint8_t* nonce, uint32_t nonce_size, sgx_report_t* p_report)
{
	sgx_status_t status;
	ms_enclave_create_report_t ms;
	ms.ms_p_qe3_target = p_qe3_target;
	ms.ms_nonce = nonce;
	ms.ms_nonce_size = nonce_size;
	ms.ms_p_report = p_report;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

