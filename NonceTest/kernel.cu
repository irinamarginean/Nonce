
#include <cuda_runtime.h>
#include "device_launch_parameters.h"

#include <stdio.h>
#include <memory.h>
#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include <bitset>
#include <vector>

using namespace std;

#define SHA_BLOCK_SIZE 20
#define INPUT "ab"
#define INPUT_SIZE 2

typedef unsigned char BYTE;
typedef unsigned int WORD;
typedef unsigned long long LONG;

const BYTE HASH_VALUE[] = {0xb7, 0x3f, 0x22, 0xd7, 0x93, 0x61, 0xce, 0xa9, 0x15, 0x1c, 0x9f, 0x7c, 0x30, 0x99, 0x3f, 0x54, 0xe6, 0xb4, 0xed, 0x1a};
const string HASH_VALUE_STRING = "b73f22d79361cea9151c9f7c30993f54e6b4ed1a";  

typedef struct {
	BYTE data[64];
	WORD datalen;
	LONG bitlen;
	WORD state[5];
	WORD k[4];
} CUDA_SHA1_CTX;

#ifndef ROTLEFT
#define ROTLEFT(a, b) (((a) << (b)) | ((a) >> (32 - (b))))
#endif

__device__ void cuda_sha1_init(CUDA_SHA1_CTX* dtx) 
{
	dtx->datalen = 0;
	dtx->bitlen = 0;
	dtx->state[0] = 0x67DE2A01;
	dtx->state[1] = 0xBB03E28C;
	dtx->state[2] = 0x011EF1DC;
	dtx->state[3] = 0x9293E9E2;
	dtx->state[4] = 0xCDEF23A9;
	dtx->k[0] = 0x5a827999;
	dtx->k[1] = 0x6ed9eba1;
	dtx->k[2] = 0x8f1bbcdc;
	dtx->k[3] = 0xca62c1d6;
}

__device__ void cuda_sha1_transform(CUDA_SHA1_CTX* dtx, const BYTE data[])
{
	WORD A, B, C, D, E, W[80], temp;

	for (int i = 0, j = 0; i < 16; i++, j += 4)
	{
		W[i] = (data[j] << 24) + (data[j + 1] << 16) + (data[j + 2] << 8) + data[j + 3];
	}

	for (int i = 16; i < 80; i++)
	{
		W[i] = W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16];
		W[i] = (W[i] << 1) | (W[i] >> 31);
	}

	A = dtx->state[0];
	B = dtx->state[1];
	C = dtx->state[2];
	D = dtx->state[3];
	E = dtx->state[4];

	for (int i = 0; i < 20; i++)
	{
		temp = ROTLEFT(A, 5) + ((B ^ C) & (~B & D)) + E + W[i] + dtx->k[0];
		E = D;
		D = C;
		C = ROTLEFT(B, 30);
		B = A;
		A = temp;
	}

	for (int i = 20; i < 40; i++)
	{
		temp = ROTLEFT(A, 5) + (B ^ C ^D) + E + W[i] + dtx->k[1];
		E = D;
		D = C;
		C = ROTLEFT(B, 30);
		B = A;
		A = temp;
	}

	for (int i = 40; i < 60; i++)
	{
		temp = ROTLEFT(A, 5) + ((B ^ C) & (B ^ D) & (C ^ D)) + E + W[i] + dtx->k[2];
		E = D;
		D = C;
		C = ROTLEFT(B, 30);
		B = A;
		A = temp;
	}

	for (int i = 60; i < 80; i++)
	{
		temp = ROTLEFT(A, 5) + (B ^ C ^D) + E + W[i] + dtx->k[3];
		E = D;
		D = C;
		C = ROTLEFT(B, 30);
		B = A;
		A = temp;
	}

	dtx->state[0] += A;
	dtx->state[1] += B;
	dtx->state[2] += C;
	dtx->state[3] += D;
	dtx->state[4] += E;
}

__device__ void cuda_sha1_update(CUDA_SHA1_CTX* dtx, const BYTE data[], LONG length)
{
	for (LONG i = 0; i < length; i++)
	{
		dtx->data[dtx->datalen] = data[i];
		dtx->datalen++;
		if (dtx->datalen == 64)
		{
			cuda_sha1_transform(dtx, dtx->data);
			dtx->bitlen += 512;
			dtx->datalen = 0;
		}
	}
}

__device__ void cuda_sha1_final(CUDA_SHA1_CTX *dtx, BYTE hash[])
{
	WORD i = dtx->datalen;

	if (dtx->datalen < 56)
	{
		dtx->data[i++] = 0x80;
		while (i < 56)	
		{
			dtx->data[i++] = 0x00;
		}
	}
	else 
	{
		dtx->data[i++] = 0x80;
		while (i < 64)
		{
			dtx->data[i++] = 0x00;
		}
		cuda_sha1_transform(dtx, dtx->data);
		memset(dtx->data, 0, 56);
	}

	dtx->bitlen += dtx->datalen * 8;
	dtx->data[63] = dtx->bitlen;
	dtx->data[62] = dtx->bitlen >> 8;
	dtx->data[61] = dtx->bitlen >> 16;
	dtx->data[60] = dtx->bitlen >> 24;
	dtx->data[59] = dtx->bitlen >> 32;
	dtx->data[58] = dtx->bitlen >> 40;
	dtx->data[57] = dtx->bitlen >> 48;
	dtx->data[56] = dtx->bitlen >> 56;
	cuda_sha1_transform(dtx, dtx->data);

	for (i = 0; i < 4; ++i) {
		hash[i]      = (dtx->state[0] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 4]  = (dtx->state[1] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 8]  = (dtx->state[2] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 12] = (dtx->state[3] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 16] = (dtx->state[4] >> (24 - i * 8)) & 0x000000ff;
	}
}

 __device__ BYTE* convert_long_to_byte(LONG number, BYTE* string, int* size)
{
	int i = 0;

	if (number == 0) {
		string[i++] = '0';
		return string;
	}

	while (number != 0) {
		int remainder = number % 10;
		string[i++] = (remainder > 9) ? (remainder - 10) + 'a' : remainder + '0';
		number = number / 10;
	}

	// reverse the string
	int begin = 0, end = *size - 1;
	while (begin < end) {
		char begin_char = *(string + begin);
		char end_char = *(string + end);
		*(string + begin) = end_char;
		*(string + end) = begin_char;
		begin++;
		end--;
	}

	*size = i;

	return string;
}

__global__ void kernel_sha1_nonce_hash(LONG* result, BYTE* hash, bool* is_found, LONG* n, BYTE* original_hash_value) 
{
	CUDA_SHA1_CTX dtx;
	BYTE output[SHA_BLOCK_SIZE];
	int nonce_size = 0;
	BYTE nonce[SHA_BLOCK_SIZE];
	BYTE hash_input[SHA_BLOCK_SIZE + INPUT_SIZE];

	unsigned int tid = threadIdx.x + blockIdx.x * blockDim.x;
	LONG nonce_input = tid + *n;

	//printf("nonce: %ld \n ", nonce_input);

	convert_long_to_byte(nonce_input, nonce, &nonce_size);

	memcpy(hash_input, (BYTE*) INPUT, INPUT_SIZE);
	memcpy(hash_input + INPUT_SIZE, nonce, nonce_size);
	memset(output, 0x0, SHA_BLOCK_SIZE);

	cuda_sha1_init(&dtx);
	cuda_sha1_update(&dtx, hash_input, INPUT_SIZE + nonce_size);
	cuda_sha1_final(&dtx, output);

	bool are_equal = true;

	for (int index = 0; index < SHA_BLOCK_SIZE; index++)
	{
		if (output[index] != original_hash_value[index])
		{
			are_equal = false;
		}
	}

	if (are_equal) 
	{
		*is_found = true;
		int i = 0;
		do 
		{
			hash[i] = output[i];
		} 
		while (output[i++] != 0);
		*result = nonce_input;
	}
}

int main()
{
	int grid_size = 256, block_size = 256;
	LONG nonce_size = sizeof(LONG);
	LONG thread_count = 0, step = 0;
	bool h_is_nonce_found = false;

	/*cudaDeviceProp device_prop;
	cudaGetDeviceProperties(&device_prop, 0);
	cudaOccupancyMaxPotentialBlockSize(&grid_size, &block_size, kernel_sha1_nonce_hash);*/

	grid_size = 256, block_size = 256;

	thread_count = grid_size * block_size;

	BYTE original_hash[SHA_BLOCK_SIZE];
	copy(begin(HASH_VALUE), end(HASH_VALUE), begin(original_hash));

	// CPU vars
	
	LONG h_found_nonce = 0;
	BYTE* h_computed_hash = (BYTE*) malloc(SHA_BLOCK_SIZE);

	memset(h_computed_hash, 0, SHA_BLOCK_SIZE);

	// CUDA vars

	LONG* d_found_nonce;
	BYTE* d_computed_hash;
	bool* d_is_nonce_found;
	BYTE* d_original_hash;
	LONG* d_step;

	cudaMalloc((void**)&d_found_nonce, sizeof(LONG));
	cudaMalloc((void**)&d_step, sizeof(LONG));
	cudaMalloc((void**)&d_computed_hash, SHA_BLOCK_SIZE);
	cudaMalloc((void**)&d_original_hash, SHA_BLOCK_SIZE);
	cudaMalloc((void**)&d_is_nonce_found, sizeof(bool));
	
	cudaMemcpy(d_is_nonce_found, &h_is_nonce_found, sizeof(bool), cudaMemcpyHostToDevice);
	cudaMemcpy(d_original_hash, &original_hash, SHA_BLOCK_SIZE, cudaMemcpyHostToDevice);
	cudaMemcpy(d_step, &step, sizeof(LONG), cudaMemcpyHostToDevice);

	string hexString;
	string hexString_nonce;

	step = 0;

	while (!h_is_nonce_found) 
	{
		kernel_sha1_nonce_hash<<<grid_size, block_size>>>(d_found_nonce, d_computed_hash, d_is_nonce_found, d_step, d_original_hash);

		cudaDeviceSynchronize();

		cudaMemcpy(&h_is_nonce_found, d_is_nonce_found, sizeof(bool), cudaMemcpyDeviceToHost);

		step += thread_count;

		cudaMemcpy(d_step, &step, sizeof(LONG), cudaMemcpyHostToDevice);
	}

	cudaMemcpy(h_computed_hash, d_computed_hash, SHA_BLOCK_SIZE, cudaMemcpyDeviceToHost);
	cudaMemcpy(&h_found_nonce, d_found_nonce, nonce_size, cudaMemcpyDeviceToHost);

	stringstream ss_nonce;
	ss_nonce << "0x" << setw(8) << setfill('0') << hex << h_found_nonce;
	string nonce_hex_string = ss_nonce.str();
		
	stringstream ss_hash;
	for (int i = 0; i < SHA_BLOCK_SIZE; i++) {
		ss_hash << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(h_computed_hash[i]);
	}

	hexString = ss_hash.str();

	cout << "Original hash: " << HASH_VALUE_STRING << endl;
	cout << "Computed hash: " << hexString << endl;

	cout << "hash in int: ";

	for (int i = 0; i < SHA_BLOCK_SIZE; i++)
	{
		cout << (int)h_computed_hash[i] << " ";
	}

	cout << endl << "===================================> NONCE: " << nonce_hex_string << endl;

	free(h_computed_hash);
	cudaFree(d_found_nonce);
	cudaFree(d_computed_hash);
	cudaFree(d_is_nonce_found);
	cudaFree(d_original_hash);
	cudaFree(d_step);
}
