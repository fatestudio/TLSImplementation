#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#include <stdint.h>
#include <time.h>
#include "tls.h"
#include "debug.h"
#include "sha256.h"
#include "Rijndael.h"

// Need to link with Ws2_32.lib, Mswsock.lib, and Advapi32.lib
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")

#define DEFAULT_BUFLEN 512
#define DEFAULT_PORT "27015"
#define MAXBLOCK_NUM 65536	// plaintext bytes <= 2^14, 2^16 blocks will be enough
#define t 16
#define q 3
#define n 12
#define PREVENT_LEN 10
using namespace std;

static SecurityParameters security_parameters;
static char *data_to_server = "This is a client test!";

// have some problem with malloc, so in order to finish the project in time, using static array...
static opaque key_block[40];
int key_block_len = 16 * 2 + 4 * 2; // 16*8=128bits AES key, 4*8=32bits IV
static opaque seed[64];
int seed_len = 64;
int r_seed_len = 1024;
uint8_t r_seed[1024];	// real seed, 32 bytes
int h_seed_len = 1024;
uint8_t h_seed[1024];	// real seed, 32 bytes
int labelUint8_len = 1024;
uint8_t labelUint8[1024];

static opaque client_write_key[16+PREVENT_LEN];
static opaque server_write_key[16+PREVENT_LEN];
static opaque client_write_IV[4+PREVENT_LEN];
static opaque server_write_IV[4+PREVENT_LEN];
static uint64_t internal_nonce_counter = 0;

static int additional_data_len = 13;
static opaque additional_data[16+PREVENT_LEN];
static int additional_data_len2 = 13;
static opaque additional_data2[16+PREVENT_LEN];
static CCMNonce nonce;
static CCMNonce nonce2;
static opaque AEADEncrypted[MAXBLOCK_NUM];
static int AEADEncrypted_len;
static unsigned char by[16+PREVENT_LEN];
static int bylen = 16;
static unsigned char by2[16+PREVENT_LEN];
static int bylen2 = 16;
char sendbuf[DEFAULT_BUFLEN];
int sendbuf_len;
char recvbuf[DEFAULT_BUFLEN];
int recvbuf_len = DEFAULT_BUFLEN;

static unsigned char blocks[MAXBLOCK_NUM];
static int block_num;
static int r;
static unsigned char ctrs[MAXBLOCK_NUM];
static int ctrs_num;
static unsigned char y[MAXBLOCK_NUM];
static unsigned char s[MAXBLOCK_NUM];
static TLSPlaintext plaintext;
static TLSCompressed compressedtext;
static TLSCiphertext ciphertext;
static TLSPlaintext plaintext2;
static TLSCompressed compressedtext2;
static TLSCiphertext ciphertext2;

// All additions are concatenations!
bool opaqueArrayAdd(opaque *oa1, int oa1_len, opaque *oa2, int oa2_len, opaque *ret, int *len){
	int i;
	*len = oa1_len + oa2_len;
	for(i = 0; i < oa1_len; i++){
		ret[i] = oa1[i];
	}
	for(i = 0; i < oa2_len; i++){
		ret[i + oa1_len] = oa2[i];
	}

	return ret;
}

bool uint8ArrayAdd(uint8_t *a1, int a1_len, uint8_t *a2, int a2_len, uint8_t *ret, int *len){
	int i;
	*len = a1_len + a2_len;
	for(i = 0; i < a1_len; i++){
		ret[i] = a1[i];
	}
	for(i = 0; i < a2_len; i++){
		ret[i + a1_len] = a2[i];
	}
	return true;
}

bool stringToOpaques(char *s, int slen, opaque *op, int *op_len){
	*op_len = slen;
	int i;
	for(i = 0; i < *op_len; i++){
		op[i] = (opaque)s[i];
	}

	return true;
}

bool stringToUint8s(char *s, int slen, uint8_t *u8, int *u8_len){
	*u8_len = slen;
	u8 = (uint8_t *)malloc((*u8_len) * sizeof(uint8_t));
	int i;
	for(i = 0; i < *u8_len; i++){
		u8[i] = (uint8_t)s[i];
	}

	return true;
}

bool uint8sToOpaques(uint8_t *u8, int u8_len, opaque *op, int *op_len){
	*op_len = u8_len;
	op = (opaque *)malloc((*op_len) * sizeof(opaque));
	int i;
	for(i = 0; i < *op_len; i++){
		op[i] = (opaque)u8[i];
	}

	return true;
}

bool opaquesToUint8s(opaque *op, int op_len, uint8_t *u8, int *u8_len){
	*u8_len = op_len;
	u8 = (uint8_t *)malloc((*u8_len) * sizeof(uint8_t));
	int i;
	for(i = 0; i < *u8_len; i++){
		u8[i] = (uint8_t)op[i];
	}

	return true;
}

uint8_t* cons_opaquesToUint8s(opaque *op, int op_len, int *u8_len){
	*u8_len = op_len;
	uint8_t *u8 = (uint8_t *)malloc((*u8_len) * sizeof(uint8_t));
	int i;
	for(i = 0; i < *u8_len; i++){
		u8[i] = (uint8_t)op[i];
	}

	return u8;
}

bool outputUint64(uint64_t sequence_number){
	int i;
	for(i = 7; i >= 0; i--){
		printf("%d", sequence_number << (8 * i) % 255);
	}
	return true;
}

bool outputUint8s(uint8_t *u8, int u8_len){
	int i;
	printf("outputUint8s: ");
	for(i = 0; i < u8_len; i++){
		printf("%u\t", u8[i]);
	}
	printf("\n");

	return true;
}

bool outputRecv(char *recvbuf, int recvbuf_len){
	int i;
	printf("Recv:\n");
	for(i = 0; i < recvbuf_len; i++){
		printf("%c", recvbuf[i]);
	}
	printf("\n");

	return true;
}

bool outputString(char *recvbuf, int recvbuf_len){
	int i;
	for(i = 0; i < recvbuf_len; i++){
		printf("%c", recvbuf[i]);
	}
	printf("\n");

	return true;
}

bool createRealSeed(uint8_t *seed, int seed_len, char *label, uint8_t *r_seed, int *r_seed_len){
	int i;
	labelUint8_len = (int)strlen(label);
	for(i = 0; i < labelUint8_len; i++){
		labelUint8[i] = (uint8_t)label[i];
	}

	uint8ArrayAdd(seed, seed_len, labelUint8, labelUint8_len, r_seed, r_seed_len);
	
	return true;
}

bool pseudoRandomFunction(opaque *secret, int secret_len, char *label, opaque *seed, int seed_len, opaque *ret, int ret_len){	
	// Using SHA256
	int i, j;
	
	createRealSeed((uint8_t *)seed, seed_len, label, r_seed, &r_seed_len);

	uint8_t digest[32];
	int digest_len = 32;
	uint8_t A[32];
	int Alen =  32;

	int iter = 0;
	if(ret_len % 32 == 0){	
		iter = ret_len / 32;
	}
	else{
		iter = ret_len / 32 + 1;
	}

	if(iter == 0){
		printf("ERROR! PRF iter = 0!\n");
		return false;
	}

	// get A[1]
	HMAC_SHA256_Buf(secret, secret_len, r_seed, r_seed_len, A);
	
	for(i = 0; i < iter; i++){
		uint8ArrayAdd(A, Alen, r_seed, r_seed_len, h_seed, &h_seed_len);
		HMAC_SHA256_Buf(secret, secret_len, h_seed, h_seed_len, digest);
		
		for(j = 0; j < digest_len; j++){
			ret[(digest_len) * i + j] = digest[j];
		}

		HMAC_SHA256_Buf(secret, secret_len, A, Alen, digest);
		
		for(j = 0; j < digest_len; j++){
			A[j] = digest[j];
		}
	}

	return true;
}

bool symmetricKeyGenerator(){
	int i;
	opaqueArrayAdd(security_parameters.server_random, 32, security_parameters.client_random, 32, seed, &seed_len);

	pseudoRandomFunction(security_parameters.master_secret, 48, "key expansion", seed, seed_len, key_block, key_block_len);

	for(i = 0; i < 16; i++){
		client_write_key[i] = key_block[i];
	}
	for(i = 0; i < 16; i++){
		server_write_key[i] = key_block[i + 16];
	}
	for(i = 0; i < 4; i++){
		client_write_IV[i] = key_block[i + 32];
	}
	for(i = 0; i < 4; i++){
		server_write_IV[i] = key_block[i + 36];
	}

	return true;
}

bool createMasterSecret(opaque *mastersecret){	// ?! need update...;
	int i;
	for(i = 0; i < 48; i++){
		mastersecret[i] = 1;
	}

	return true;
} 

bool createSecurityParameters(){
	// AEAD_AES_128_CCM
    security_parameters.entity = client;
    security_parameters.prf_algorithm = tls_prf_sha256;
    security_parameters.cipher_type = aead;
    security_parameters.enc_key_length = 16;
	
	// generate client random
	opaque client_secret = 1;
	int client_secret_len = 1;
	char *client_label = "client";
	opaque client_seed = 2;
	int client_seed_len = 1;
	pseudoRandomFunction(&client_secret, client_secret_len, client_label, &client_seed, client_seed_len, security_parameters.client_random, 32);

	// generate server random
	opaque server_secret = 3;
	int server_secret_len = 1;
	char *server_label = "server";
	opaque server_seed = 4;
	int server_seed_len = 1;
	pseudoRandomFunction(&server_secret, server_secret_len, server_label, &server_seed, server_seed_len, security_parameters.server_random, 32);

	createMasterSecret(security_parameters.master_secret);

	return true;
}

bool createNonce(){
	nonce.seq_num = internal_nonce_counter;
	internal_nonce_counter++;
	nonce.write_IV = server_write_IV[0] + (server_write_IV[1] << 8) + (server_write_IV[2] << 16) + (server_write_IV[3] << 24);
	
	return true;
}

bool createNonce2(){
	nonce2.seq_num = ciphertext.fragment.nonce_explicit;
	nonce2.write_IV = client_write_IV[0] + (client_write_IV[1] << 8) + (client_write_IV[2] << 16) + (client_write_IV[3] << 24);

	return true;
}

bool constructTLSPlaintext(){
	int i;
	plaintext.type = application_data;
	plaintext.version.minor = 255;	// TBD
	plaintext.version.major = 255;	// TBD
	
	plaintext.length = strlen(data_to_server);
	for(i = 0; i < plaintext.length; i++){
		plaintext.fragment[i] = data_to_server[i];
	}
	
	return true;
}

bool plainToCompressed(TLSPlaintext plaintext){
	if(security_parameters.compression_algorithm == nullComp){
		int i;
		compressedtext.type = application_data;
		compressedtext.version = plaintext.version;
		compressedtext.length = plaintext.length;
		for(i = 0; i < plaintext.length; i++){
			compressedtext.fragment[i] = plaintext.fragment[i];
		}
		return true;
	}
	return false;
}

bool constructTLSCiphertext(opaque *AEADEncrypted, int AEADEncrypted_len){
	int i;

	ciphertext.type = compressedtext.type;
	ciphertext.version = compressedtext.version;
	ciphertext.length = AEADEncrypted_len;
	ciphertext.fragment.nonce_explicit = nonce.seq_num;
	for(i = 0; i < ciphertext.length; i++){
		ciphertext.fragment.content[i] = AEADEncrypted[i];
	}

	return true;
}

bool createAdditionalData(){
	additional_data[0] = nonce.seq_num % 255;
	additional_data[1] = (nonce.seq_num >> 8) % 255;
	additional_data[2] = (nonce.seq_num >> 16) % 255;
	additional_data[3] = (nonce.seq_num >> 24) % 255;
	additional_data[4] = (nonce.seq_num >> 32) % 255;
	additional_data[5] = (nonce.seq_num >> 40) % 255;
	additional_data[6] = (nonce.seq_num >> 48) % 255;
	additional_data[7] = (nonce.seq_num >> 56) % 255;

	additional_data[8] = compressedtext.type;
	additional_data[9] = compressedtext.version.major;
	additional_data[10] = compressedtext.version.minor;
	additional_data[11] = compressedtext.length % 255;
	additional_data[12] = compressedtext.length / 255;

	additional_data_len = 13;

	return true;
}

bool createAdditionalData2(){
	additional_data2[0] = nonce2.seq_num % 255;
	additional_data2[1] = (nonce2.seq_num >> 8) % 255;
	additional_data2[2] = (nonce2.seq_num >> 16) % 255;
	additional_data2[3] = (nonce2.seq_num >> 24) % 255;
	additional_data2[4] = (nonce2.seq_num >> 32) % 255;
	additional_data2[5] = (nonce2.seq_num >> 40) % 255;
	additional_data2[6] = (nonce2.seq_num >> 48) % 255;
	additional_data2[7] = (nonce2.seq_num >> 56) % 255;

	additional_data2[8] = ciphertext.type;
	additional_data2[9] = ciphertext.version.major;
	additional_data2[10] = ciphertext.version.minor;
	additional_data2[11] = ciphertext.length % 255;
	additional_data2[12] = ciphertext.length / 255;

	additional_data_len2 = 13;

	return true;
}

bool formatFunc(opaque *plaintext, int plaintext_len, CCMNonce nonce, opaque *associatedata, int associate_len){
	int i;

	block_num = 1;
	blocks[0] = 0;
	// reserved bit = 0
	if(associate_len > 0){	// adata
		blocks[0] = blocks[0] | (1 << 6);
	}
	unsigned char tbit = 0;
	tbit = (t - 2) / 2;
	blocks[0] = blocks[0] | ((tbit) << 3);
	unsigned char qbit = 0;
	qbit = q - 1;
	blocks[0] = blocks[0] | qbit;

	// N
	for(i = 0; i < 4; i++){
		blocks[block_num + i] = (nonce.write_IV >> (i * 8)) % 255;
	}
	block_num += 4;
	for(i = 0; i < 8; i++){
		blocks[block_num + i] = (nonce.seq_num >> (i * 8)) % 255;
	}
	block_num += 8;

	// plaintext_len
	for(i = 0; i < 3; i++){
		blocks[block_num + i] = (plaintext_len >> (i * 8)) % 255;
	}
	block_num += 3;

	// associate data
	if(associate_len == 0){
		printf("Associate data should not be empty!\n");
		return false;
	}
	else if(associate_len <= 4){	// 32 bits
		int value = associatedata[0];
		if(value < 2^16 - 2^8){
			blocks[block_num] = associatedata[0];
			block_num++;
			blocks[block_num] = associatedata[1];
			block_num++;		
		}
		else{
			blocks[block_num] = 0xff;
			block_num++;
			blocks[block_num] = 0xfe;
			block_num++;
			blocks[block_num] = associatedata[0];
			block_num++;
			blocks[block_num] = associatedata[1];
			block_num++;	
			blocks[block_num] = associatedata[2];
			block_num++;
			blocks[block_num] = associatedata[3];
			block_num++;	
		}
	}
	else if(associate_len <= 8){	// 64 bits
			blocks[block_num] = 0xff;
			block_num++;
			blocks[block_num] = 0xff;
			block_num++;
			for(i = 0; i < 8; i++){
				blocks[block_num] = associatedata[i];
				block_num++;
			}
	}

	// plaintext
	for(i = 0; i < plaintext_len; i++){
		blocks[block_num] = plaintext[i];
		block_num++;
	}
	
	while(block_num % 16 != 0){
		blocks[block_num] = 0;
		block_num++;
	}

	return true;
}

bool counterFunc(int m, CCMNonce nonce){

	int i, j;
	int ctr_num = m;

	ctrs_num = 0;
	for(i = 0; i < ctr_num; i++){
		ctrs[ctrs_num] = q - 1;
		ctrs_num++;

		// N
		for(j = 0; j < 4; j++){
			ctrs[ctrs_num + j] = nonce.write_IV >> (j * 8) % 255;
		}
		ctrs_num += 4;
		for(j = 0; j < 8; j++){
			ctrs[ctrs_num + j] = nonce.seq_num >> (j * 8) % 255;
		}
		ctrs_num += 8;
		
		if(i < 256){
			int emptyn = 2;

			ctrs[ctrs_num] = i;
			ctrs_num++;

			for(j = 0; j < emptyn; j++){
				ctrs[ctrs_num] = 0;
				ctrs_num++;
			}
		}
		else if(i < 256 * 256){
			int emptyn = 1;
			
			ctrs[ctrs_num] = i % 256;
			ctrs_num++;

			ctrs[ctrs_num] = i / 256;
			ctrs_num++;

			for(j = 0; j < emptyn; j++){
				ctrs[ctrs_num] = 0;
				ctrs_num++;
			}

		}
		else if(i < 256 * 256 * 256){
			ctrs[ctrs_num] = i % 256;
			ctrs_num++;

			ctrs[ctrs_num] = (i / 256) % 256;
			ctrs_num++;

			ctrs[ctrs_num] = i / (256 * 256);
			ctrs_num++;
		}
	}

	return true;
}

bool blockXorAdd(char *b1, char *b2, char *br, int len){
	for(int i = 0; i < len; i++){
		br[i] = b1[i] ^ b2[i];
	}
	return true;
}

bool AEAD_Encrypt(opaque *write_key, CCMNonce nonce, opaque *plaintext, int plaintext_len, opaque *additional_data, int additional_data_len, opaque *AEADEncrypted, int *AEADEncrypted_len){
	unsigned char tag[t];
	int m;
	int i;

	// generate blocks[]
	formatFunc(plaintext, plaintext_len, nonce, additional_data, additional_data_len);

	CRijndael oRijndael;
	oRijndael.MakeKey((char *)write_key, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16, 16);

	// generate y[]
	for(i = 0; i < block_num; i++){
		y[i] = 0;
	}
	oRijndael.EncryptBlock((char *)&(blocks[0]), (char *)&(y[0]));	
	for(i = 1; i < block_num / 16; i++){
		blockXorAdd((char *)&(blocks[i*16]), (char *)&(y[i*16]), (char *)by, 16);
		oRijndael.EncryptBlock((char *)by, (char *)&(y[i*16]));	
	}

	// generate tag;
	for(i = 0; i < t; i++){
		tag[i] = y[block_num - 16 + i];
	}

	if(plaintext_len % 128 == 0){
		m = plaintext_len / 128;
	}
	else{
		m = plaintext_len / 128 + 1;
	}
	// generate ctrs[]
	counterFunc(m, nonce);

	// generate s[]
	for(i = 0; i < m; i++){
		oRijndael.EncryptBlock((char *)&(ctrs[i*16]), (char *)&(s[i*16]));	
	}

	blockXorAdd((char *)plaintext, (char *)s, (char *)AEADEncrypted, plaintext_len);
	blockXorAdd((char *)tag, (char *)s, (char *)&(AEADEncrypted[plaintext_len]), t);
	*AEADEncrypted_len = plaintext_len + t;

	printf("Plaintext Sent\n");
	outputString((char *)plaintext, plaintext_len);
	printf("\n");

	return true;
}

bool AEAD_Decrypt(opaque *write_key, CCMNonce nonce, opaque *plaintext, uint16_t *plaintext_len, opaque *additional_data, int additional_data_len, opaque *ciphertext, int ciphertext_len){
	unsigned char tag[t];
	int m;
	int i;
	int p_len;
	CRijndael oRijndael;
	oRijndael.MakeKey((char *) write_key, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16, 16);
	
	if(ciphertext_len < t) 
		return false;

	p_len = ciphertext_len - t;

	*plaintext_len = p_len;
	if(p_len % 128 == 0){
		m = p_len / 128;
	}
	else{
		m = p_len / 128 + 1;
	}
	// generate ctrs[]
	counterFunc(m, nonce);
	
	// generate s[]
	for(i = 0; i < m; i++){
		oRijndael.EncryptBlock((char *)&(ctrs[i*16]), (char *)&(s[i*16]));	
	}

	blockXorAdd((char *)ciphertext, (char *)s, (char *)plaintext, p_len);

	blockXorAdd((char *)&(ciphertext[p_len]), (char *)s, (char *)tag, t);

	// generate blocks[]
	formatFunc(plaintext, p_len, nonce, additional_data, additional_data_len);

	// generate y[]
	for(i = 0; i < block_num; i++){
		y[i] = 0;
	}
	oRijndael.EncryptBlock((char *)&(blocks[0]), (char *)&(y[0]));
	for(i = 1; i < block_num / 16; i++){
		blockXorAdd((char *)&(blocks[i*16]), (char *)&(y[i*16]), (char *)by, 16);
		oRijndael.EncryptBlock((char *)by, (char *)&(y[i*16]));	
	}
	
	for(i = 0; i < 16; i++){
		if(tag[i] != y[block_num - 16 + i]) 
			return false;
	}
	return true;
}

bool stringToSecurityParameters(char *recvbuf, int recvbuf_len){
	int i;
	if(recvbuf[0] == 0){
		security_parameters.entity = server;
	}
	else if(recvbuf[1] == 1){
		security_parameters.entity = client;
	}
	else{ 
		return false;
	}
	if(recvbuf[1] == 1){
		security_parameters.prf_algorithm = tls_prf_sha256;
	}
	else{
		return false;
	}
	if(recvbuf[2] == 0){
		security_parameters.bulk_cipher_algorithm = nullBulk;
	}
	else if(recvbuf[2] == 1){
		security_parameters.bulk_cipher_algorithm = rc4;
	}
	else if(recvbuf[2] == 2){
		security_parameters.bulk_cipher_algorithm = des3;
	}
	else if(recvbuf[2] == 3){
		security_parameters.bulk_cipher_algorithm = aes;
	}
	if(recvbuf[3] == 1){
		security_parameters.cipher_type = stream;
	}
	else if(recvbuf[3] == 2){
		security_parameters.cipher_type = block;
	}
	else if(recvbuf[3] == 3){
		security_parameters.cipher_type = aead;
	}
	security_parameters.enc_key_length = recvbuf[4];
	security_parameters.block_length = recvbuf[5];
	security_parameters.fixed_iv_length = recvbuf[6];
	security_parameters.record_iv_length = recvbuf[7];
	if(recvbuf[8] == 0){
		security_parameters.mac_algorithm = nullMAC;
	}
	else if(recvbuf[8] == 1){
		security_parameters.mac_algorithm = hmac_md5;
	}
	else if(recvbuf[8] == 2){
		security_parameters.mac_algorithm = hmac_sha1;
	}
	else if(recvbuf[8] == 3){
		security_parameters.mac_algorithm = hmac_sha256;
	}
	else if(recvbuf[8] == 4){
		security_parameters.mac_algorithm = hmac_sha384;
	}
	else if(recvbuf[8] == 5){
		security_parameters.mac_algorithm = hmac_sha512;
	}
	else if(recvbuf[8] == 6){
		security_parameters.mac_algorithm = aes_128_ccm;
	}
	if(recvbuf[9] == 0){
		security_parameters.compression_algorithm = nullComp;
	}
	else if(recvbuf[9] == 255){
		security_parameters.compression_algorithm = comp;
	}

	for(i = 0; i < 48; i++){
		security_parameters.master_secret[i] = recvbuf[10 + i];
	}
	for(i = 0; i < 32; i++){
		security_parameters.client_random[i] = recvbuf[10 + 48 + i];
	}
	for(i = 0; i < 32; i++){
		security_parameters.server_random[i] = recvbuf[10 + 48 + 32 + i];
	}

	return true;
}

bool securityParametersToString(char *sendbuf, int *sendbuf_len){
	int i;
	sendbuf[0] = security_parameters.entity;
	sendbuf[1] = security_parameters.prf_algorithm;
	sendbuf[2] = security_parameters.bulk_cipher_algorithm;
	sendbuf[3] = security_parameters.cipher_type;
	sendbuf[4] = security_parameters.enc_key_length;
	sendbuf[5] = security_parameters.block_length;
	sendbuf[6] = security_parameters.fixed_iv_length;
	sendbuf[7] = security_parameters.record_iv_length;
	sendbuf[8] = security_parameters.mac_algorithm;
	sendbuf[9] = security_parameters.compression_algorithm;
	for(i = 0; i < 48; i++){
		sendbuf[10 + i] = security_parameters.master_secret[i];
	}
	for(i = 0; i < 32; i++){
		sendbuf[10 + 48 + i] = security_parameters.client_random[i];
	}
	for(i = 0; i < 32; i++){
		sendbuf[10 + 48 + 32 + i] = security_parameters.server_random[i];
	}

	*sendbuf_len = 10 + 48 + 32 + 32;

	return true;
}

bool TLSCiphertextToString(char *sendbuf, int *sendbuf_len){
	int i;
	sendbuf[0] = ciphertext.type;
	sendbuf[1] = ciphertext.version.major;
	sendbuf[2] = ciphertext.version.minor;
	sendbuf[3] = ciphertext.length % 255;
	sendbuf[4] = ciphertext.length / 255 % 255;
	sendbuf[5] = ciphertext.fragment.nonce_explicit % 255;
	sendbuf[6] = (ciphertext.fragment.nonce_explicit >> 8) % 255;
	sendbuf[7] = (ciphertext.fragment.nonce_explicit >> 16) % 255;
	sendbuf[8] = (ciphertext.fragment.nonce_explicit >> 24) % 255;
	sendbuf[9] = (ciphertext.fragment.nonce_explicit >> 32) % 255;
	sendbuf[10] = (ciphertext.fragment.nonce_explicit >> 40) % 255;
	sendbuf[11] = (ciphertext.fragment.nonce_explicit >> 48) % 255;
	sendbuf[12] = (ciphertext.fragment.nonce_explicit >> 56) % 255;
	for(i = 0; i < ciphertext.length; i++){
		sendbuf[13 + i] = ciphertext.fragment.content[i];
	}
	*sendbuf_len = 13 + ciphertext.length;
	return true;
}

bool stringToTLSCiphertext(char *recvbuf, int recvbuf_len){
	int i;
	if(recvbuf[0] == 20){
		ciphertext2.type = change_cipher_spec;
	}
	else if(recvbuf[0] == 21){
		ciphertext2.type = alert;
	}
	else if(recvbuf[0] == 22){
		ciphertext2.type = handshake;
	}
	else if(recvbuf[0] == 23){
		ciphertext2.type = application_data;
	}
	else if(recvbuf[0] == 255){
		ciphertext2.type = maxTYPE;
	}
	ciphertext2.version.major = recvbuf[1];
	ciphertext2.version.minor = recvbuf[2];
	ciphertext2.length = recvbuf[3] + (recvbuf[4] << 8);
	ciphertext2.fragment.nonce_explicit = recvbuf[5] + (recvbuf[6] << 8) + (recvbuf[7] << 16) + (recvbuf[8] << 24) + 
		(recvbuf[9] << 32) + (recvbuf[10] << 40) + (recvbuf[11] << 48) + (recvbuf[12] << 56);

	for(i = 0; i < ciphertext2.length; i++){
		ciphertext2.fragment.content[i] = recvbuf[13 + i];
	}

	return true;
}

// For Handshake Protocols: TODO...
// TODO
Random random_new(){	// ?! need to be updated...
	Random random;
	random.gmt_unix_time = 10;
	random.random_bytes[0] = 10;
	return random;
}
// Client's
// TODO
bool generateClientHello(char *sendbuf, int *sendbuf_len){
	return true;
}
// TODO
bool parseServerHello(char *recvbuf, int recvbuf_len){
	return true;
}
// TODO
bool parseServerCertificate(char *recvbuf, int recvbuf_len){
	return true;
}
// TODO
bool parseServerKeyExchange(char *recvbuf, int recvbuf_len){
	return true;
}
// TODO
bool parseServerHelloDone(char *recvbuf, int recvbuf_len){
	return true;
}
// TODO
bool generateClientCeritificate(char *sendbuf, int *sendbuf_len){
	return true;
}
// TODO
bool generateClientKeyExchange(char *sendbuf, int *sendbuf_len){
	return true;
}
// TODO
bool generateClientCertificateVerify(char *sendbuf, int *sendbuf_len){
	return true;
}
// TODO
bool generateClientFinishedMessage(char *sendbuf, int *sendbuf_len){
	return true;
}
// TODO
bool parseServerFinishedMessage(char *recvbuf, int recvbuf_len){
	return true;
}

// Server's
// TODO
bool parseClientHello(char *recvbuf, int recvbuf_len){
	return true;
}
// TODO
bool generateServerHello(char *sendbuf, int *sendbuf_len){
	return true;
}
// TODO
bool generateServerCertificate(char *sendbuf, int *sendbuf_len){
	return true;
}
// TODO
bool generateServerKeyExchange(char *sendbuf, int *sendbuf_len){
	return true;
}
// TODO
bool generateServerHelloDone(char *sendbuf, int *sendbuf_len){
	return true;
}
// TODO
bool parseClientCertificate(char *recvbuf, int recvbuf_len){
	return true;
}
// TODO
bool parseClientKeyExchange(char *recvbuf, int recvbuf_len){
	return true;
}
// TODO
bool parseClientCertificateVerify(char *recvbuf, int recvbuf_len){
	return true;
}
// TODO
bool parseClientFinishedMessage(char *recvbuf, int recvbuf_len){
	return true;
}
// TODO
bool generateServerFinishedMessage(char *sendbuf, int *sendbuf_len){
	return true;
}

int __cdecl main(int argc, char **argv) 
{
	ClientPhase clientphase;
	bool whileflag;
    WSADATA wsaData;
    SOCKET ConnectSocket = INVALID_SOCKET;
    struct addrinfo *result = NULL,
                    *ptr = NULL,
                    hints;
	int iResult;
    
    // Validate the parameters
    if (argc != 2) {
        printf("usage: %s server-name\n", argv[0]);
        return 1;
    }

    // Initialize Winsock
    iResult = WSAStartup(MAKEWORD(2,2), &wsaData);
    if (iResult != 0) {
        printf("WSAStartup failed with error: %d\n", iResult);
        return 1;
    }

    ZeroMemory( &hints, sizeof(hints) );
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    // Resolve the server address and port
    iResult = getaddrinfo(argv[1], DEFAULT_PORT, &hints, &result);
    if ( iResult != 0 ) {
        printf("getaddrinfo failed with error: %d\n", iResult);
        WSACleanup();
        return 1;
    }

    // Attempt to connect to an address until one succeeds
    for(ptr=result; ptr != NULL ;ptr=ptr->ai_next) {

        // Create a SOCKET for connecting to server
        ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype, 
            ptr->ai_protocol);
        if (ConnectSocket == INVALID_SOCKET) {
            printf("socket failed with error: %ld\n", WSAGetLastError());
            WSACleanup();
            return 1;
        }

        // Connect to server.
        iResult = connect( ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
        if (iResult == SOCKET_ERROR) {
            closesocket(ConnectSocket);
            ConnectSocket = INVALID_SOCKET;
            continue;
        }
        break;
    }

    freeaddrinfo(result);

    if (ConnectSocket == INVALID_SOCKET) {
        printf("Unable to connect to server!\n");
        WSACleanup();
        return 1;
    }
	
	// while loop for tls
	clientphase = InitialC;
	whileflag = true;
	while(whileflag){
		switch (clientphase) {
		case TestC: {
			strcpy(sendbuf, "Client Test");
			sendbuf_len = strlen(sendbuf);
			printf("%d\n%s\n", sendbuf_len, sendbuf);
			send( ConnectSocket, sendbuf, sendbuf_len, 0 ); 
			
			recvbuf_len = recv(ConnectSocket, recvbuf, recvbuf_len, 0);
			printf("Client Test Recv:\n");
			printf("%d\n", recvbuf_len);
			outputRecv(recvbuf, recvbuf_len);

			clientphase = ExitC;
			break;
				   }
		case InitialC: {
			if(localtest && recordOnly){
				createSecurityParameters();
				clientphase = RecordPrepareC;
			}
			else if(recordOnly){
				recvbuf_len = recv(ConnectSocket, recvbuf, recvbuf_len, 0);
				stringToSecurityParameters(recvbuf, recvbuf_len);
				printf("Security Parameters Received\n");

				clientphase = RecordPrepareC;
			}
			else {
				// TODO: handshake protocol initialization... 
			}
			printf("InitialC Finished\n");
			break;
					  }
		case HandshakeWaitServerHello: {
			recvbuf_len = recv(ConnectSocket, recvbuf, recvbuf_len, 0);
			parseServerHello(recvbuf, recvbuf_len);
			recvbuf_len = recv(ConnectSocket, recvbuf, recvbuf_len, 0);
			parseServerCertificate(recvbuf, recvbuf_len);
			recvbuf_len = recv(ConnectSocket, recvbuf, recvbuf_len, 0);
			parseServerKeyExchange(recvbuf, recvbuf_len);
			recvbuf_len = recv(ConnectSocket, recvbuf, recvbuf_len, 0);
			parseServerHelloDone(recvbuf, recvbuf_len);

			generateClientKeyExchange(sendbuf, &sendbuf_len);
			send(ConnectSocket, sendbuf, sendbuf_len, 0);
			generateClientCertificateVerify(sendbuf, &sendbuf_len);
			send(ConnectSocket, sendbuf, sendbuf_len, 0);
			generateClientFinishedMessage(sendbuf, &sendbuf_len);
			send(ConnectSocket, sendbuf, sendbuf_len, 0);
			clientphase = HandshakeWaitServerFinishedMessage;
			break;
									   }
		case HandshakeWaitServerFinishedMessage: {
			recvbuf_len = recv(ConnectSocket, recvbuf, recvbuf_len, 0);
			parseServerFinishedMessage(recvbuf, recvbuf_len);
			clientphase = RecordLayerC;
			break;
									   }
		case RecordPrepareC: {
			symmetricKeyGenerator();
			clientphase = RecordLayerC;
			printf("RecordPrepareC Finished\n");
			break;
							}
		case RecordLayerC: {
			if(localtest){
				constructTLSPlaintext();
				plainToCompressed(plaintext);
				
				createNonce();
				createAdditionalData();
				AEAD_Encrypt(client_write_key, nonce, plaintext.fragment, plaintext.length, additional_data, additional_data_len, AEADEncrypted, &AEADEncrypted_len);
				constructTLSCiphertext(AEADEncrypted, AEADEncrypted_len);
				TLSCiphertextToString(recvbuf, &recvbuf_len);
				printf("Client RecordLayer Send Finished\n");

				printf("Server Ciphertext Received:\t%d\n", recvbuf_len);
				outputUint8s((uint8_t *)recvbuf, recvbuf_len);

				stringToTLSCiphertext(recvbuf, recvbuf_len);	
				createNonce2();
				createAdditionalData2();

				// TODO: add compressedtext initialization; add compressedToPlaintext()
				bool valid = AEAD_Decrypt(client_write_key, nonce2, compressedtext2.fragment, &(compressedtext2.length), additional_data2, additional_data_len2, ciphertext2.fragment.content, ciphertext2.length);
				printf("\nPlaintext Valid? %s\n", (valid) ? "true" : "false");
			}
			else{
				constructTLSPlaintext();
				plainToCompressed(plaintext);
				createNonce();
				createAdditionalData();
				AEAD_Encrypt(client_write_key, nonce, compressedtext.fragment, compressedtext.length, additional_data, additional_data_len, AEADEncrypted, &AEADEncrypted_len);
				constructTLSCiphertext(AEADEncrypted, AEADEncrypted_len);
				TLSCiphertextToString(sendbuf, &sendbuf_len);

				send(ConnectSocket, sendbuf, sendbuf_len, 0);
				printf("Client RecordLayer Send Finished\n");

				recvbuf_len = recv(ConnectSocket, recvbuf, recvbuf_len, 0);
				printf("Server Ciphertext Received:\t%d\n", recvbuf_len);
				outputUint8s((uint8_t *)recvbuf, recvbuf_len);

				stringToTLSCiphertext(recvbuf, recvbuf_len);	
				createNonce2();
				createAdditionalData2();
				
				bool valid = AEAD_Decrypt(server_write_key, nonce2, compressedtext2.fragment, &compressedtext2.length, additional_data2, additional_data_len2, ciphertext2.fragment.content, ciphertext2.length);
				printf("Plaintext Valid? %s\nPlaintext\n", (valid) ? "true" : "false");
				outputRecv((char *)compressedtext2.fragment, compressedtext2.length);
			}
			printf("RecordLayer Finished\n");
			clientphase = ExitC;
			break;
						  }
		case ExitC:{
			// shutdown the connection since no more data will be sent
			iResult = shutdown(ConnectSocket, SD_SEND);
			if (iResult == SOCKET_ERROR) {
				printf("shutdown failed with error: %d\n", WSAGetLastError());
				closesocket(ConnectSocket);
				WSACleanup();
				return 1;
			}
			whileflag = false;
			break;
				   }
		}
	}

    // cleanup
    closesocket(ConnectSocket);
    WSACleanup();

    return 0;
}
