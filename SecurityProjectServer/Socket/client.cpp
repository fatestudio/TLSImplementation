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

using namespace std;

static SecurityParameters security_parameters;
static char *data_to_server = "This is a test!";

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

static opaque client_write_key[16];
static opaque server_write_key[16];
static opaque client_write_IV[4];
static opaque server_write_IV[4];
static uint64_t internal_nonce_counter = 0;

int additional_data_len = 13;
opaque additional_data[16];
CCMNonce nonce;
opaque AEADEncrypted[MAXBLOCK_NUM];
int AEADEncrypted_len;
unsigned char by[16];
int bylen = 16;
unsigned char by2[16];
int bylen2 = 16;

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

bool int64ToOpaques(uint64_t internal_sequence_number, opaque *result){
	result[0] = internal_sequence_number % 255;
	result[1] = internal_sequence_number / 255 % 255;
	result[2] = internal_sequence_number / 255 / 255 % 255;
	result[3] = internal_sequence_number / 255 / 255 / 255;

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

bool outputUint8s(uint8_t *u8, int u8_len){
	int i;
	printf("outputUint8s: ");
	for(i = 0; i < u8_len; i++){
		printf("%u\t", u8[i]);
	}
	printf("\n");

	return true;
}

bool createRealSeed(uint8_t *seed, int seed_len, char *label, uint8_t *r_seed, int *r_seed_len){
	int i;

	for(i = 0; i < labelUint8_len; i++){
		labelUint8[i] = (uint8_t)label[i];
	}

	uint8ArrayAdd(seed, seed_len, labelUint8, labelUint8_len, r_seed, r_seed_len);
	
	return true;
}

bool pseudoRandomFunction(opaque *secret, int secret_len, char *label, opaque *seed, int seed_len, opaque *ret, int ret_len){	
	// Using SHA256
	int i, j;
	// malloc for return value
	int maxl;
	if(ret_len % 32 == 0){	
		maxl = ret_len;
	}
	else{
		maxl = ret_len / 32 * 32 + 32;
	}
	
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

	printf("pseudoRandomFunction final ret\n");
	outputUint8s(ret, ret_len);
	return true;
}

bool symmetricKeyGenerator(){
	int i;
	opaqueArrayAdd(security_parameters.server_random, 32, security_parameters.client_random, 32, seed, &seed_len);

	pseudoRandomFunction(security_parameters.master_secret, 48, "key expansion", seed, seed_len, key_block, key_block_len);
	printf("key block\n");
	outputUint8s(key_block, key_block_len);
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
	printf("security_para.client_random\n");
	outputUint8s(security_parameters.client_random, 32);

	// generate server random
	opaque server_secret = 3;
	int server_secret_len = 1;
	char *server_label = "server";
	opaque server_seed = 4;
	int server_seed_len = 1;
	pseudoRandomFunction(&server_secret, server_secret_len, server_label, &server_seed, server_seed_len, security_parameters.server_random, 32);
	printf("security_para.server_random\n");
	outputUint8s(security_parameters.server_random, 32);

	createMasterSecret(security_parameters.master_secret);

	return true;
}

bool constructTLSPlaintext(){
	printf("In constructTLSP\n");
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
	ciphertext.fragment.nonce_explicit = nonce.write_IV;
	for(i = 0; i < ciphertext.length; i++){
		ciphertext.fragment.content[i] = AEADEncrypted[i];
	}

	return true;
}

bool createAdditionalData(){
	additional_data[0] = nonce.seq_num % 255;
	additional_data[1] = nonce.seq_num >> 8 % 255;
	additional_data[2] = nonce.seq_num >> 16 % 255;
	additional_data[3] = nonce.seq_num >> 24 % 255;
	additional_data[4] = nonce.seq_num >> 32 % 255;
	additional_data[5] = nonce.seq_num >> 40 % 255;
	additional_data[6] = nonce.seq_num >> 48 % 255;
	additional_data[7] = nonce.seq_num >> 56 % 255;

	additional_data[8] = compressedtext.type;
	additional_data[9] = compressedtext.version.major;
	additional_data[10] = compressedtext.version.minor;
	additional_data[11] = compressedtext.length % 255;
	additional_data[12] = compressedtext.length / 255;

	printf("additional data:\n");
	outputUint8s(additional_data, additional_data_len);

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
		blocks[block_num + i] = nonce.write_IV >> i % 2;
	}
	block_num += 4;
	for(i = 0; i < 8; i++){
		blocks[block_num + i] = nonce.seq_num >> i % 2;
	}
	block_num += 8;

	// plaintext_len
	for(i = 0; i < 3; i++){
		blocks[block_num + i] = plaintext_len >> i % 2;
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
		for(i = 0; i < 4; i++){
			blocks[block_num + i] = nonce.write_IV >> i % 2;
		}
		block_num += 4;
		for(i = 0; i < 8; i++){
			blocks[block_num + i] = nonce.seq_num >> i % 2;
		}
		block_num += 8;
		
		if(i < 256){
			int emptyn = 2;
			for(j = 0; j < emptyn; j++){
				ctrs[ctrs_num] = 0;
				ctrs_num++;
			}

			ctrs[ctrs_num] = i;
			ctrs_num++;
		}
		else if(i < 256 * 256){
			int emptyn = 1;
			for(j = 0; j < emptyn; j++){
				ctrs[ctrs_num] = 0;
				ctrs_num++;
			}

			ctrs[ctrs_num] = i / 256;
			ctrs_num++;

			ctrs[ctrs_num] = i % 256;
			ctrs_num++;
		}
		else if(i < 256 * 256 * 256){
			ctrs[ctrs_num] = i / (256 * 256);
			ctrs_num++;

			ctrs[ctrs_num] = (i / 256) % 256;
			ctrs_num++;

			ctrs[ctrs_num] = i % 256;
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
	printf("\nB:\n");
	outputUint8s(blocks, block_num);
	printf("\n");

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
	printf("Y:\n");
	outputUint8s(y, block_num);

	// generate tag;
	for(i = 0; i < t; i++){
		tag[i] = y[block_num - 16 + i];
	}

	printf("tag\n");
	outputUint8s(tag, 16);

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

	printf("Plaintext\n");
	outputUint8s(plaintext, plaintext_len);

	printf("AEADEncrypted\n");
	outputUint8s(AEADEncrypted, *AEADEncrypted_len);

	return true;
}

bool AEAD_Decrypt(opaque *write_key, CCMNonce nonce, opaque *plaintext, int *plaintext_len, opaque *additional_data, int additional_data_len, opaque *ciphertext, int ciphertext_len){
	unsigned char tag[t];
	int m;
	int i;
	int p_len;
	CRijndael oRijndael;
	oRijndael.MakeKey((char *) write_key, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16, 16);
	
	if(ciphertext_len < t) 
		return false;

	p_len = ciphertext_len - t;
	printf("plaintext_len:%d\n", p_len);

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
	printf("Decrypted Plaintext\n");
	outputUint8s(plaintext, p_len);
	printf("plaintext.length:%d\n", *plaintext_len);	// a bug ...

	blockXorAdd((char *)&(ciphertext[p_len]), (char *)s, (char *)tag, t);

	printf("Decrypted tag\n");
	outputUint8s(tag, 16);

	// generate blocks[]
	formatFunc(plaintext, p_len, nonce, additional_data, additional_data_len);
	printf("\nB:\n");
	outputUint8s(blocks, block_num);
	printf("\n");

	// generate y[]
	for(i = 0; i < block_num; i++){
		y[i] = 0;
	}
	oRijndael.EncryptBlock((char *)&(blocks[0]), (char *)&(y[0]));
	for(i = 1; i < block_num / 16; i++){
		blockXorAdd((char *)&(blocks[i*16]), (char *)&(y[i*16]), (char *)by, 16);
		oRijndael.EncryptBlock((char *)by, (char *)&(y[i*16]));	
	}
	printf("Y:\n");
	outputUint8s(y, block_num);
	
	for(i = 0; i < 16; i++){
		if(tag[i] != y[block_num - 16 + i]) 
			return false;
	}
	return true;
}

Random random_new(){	// ?! need to be updated...
	Random random;
	random.gmt_unix_time = 10;
	random.random_bytes[0] = 10;
	return random;
}

bool generateClientHello(char *sendbuf){
	return true;
}

bool parseServerHello(char *recvbuf){
	return true;
}

bool parseServerCertificate(char *recvbuf){
	return true;
}

bool parseServerKeyExchange(char *recvbuf){
	return true;
}

bool parseServerHelloDone(char *recvbuf){
	return true;
}

bool generateClientKeyExchange(char *sendbuf){
	return true;
}

bool generateClientCertificateVerify(char *sendbuf){
	return true;
}

bool generateClientFinishedMessage(char *sendbuf){
	return true;
}

bool parseServerFinishedMessage(char *recvbuf){
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
    char *sendbuf;
    char recvbuf[DEFAULT_BUFLEN];
    int iResult;
    int recvbuflen = DEFAULT_BUFLEN;
    /*
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
	*/

	// while loop for tls
	clientphase = InitialC;
	whileflag = true;
	while(whileflag){
		switch (clientphase) {
		case TestC: {
			sendbuf = "Client Test";
			send( ConnectSocket, sendbuf, (int)strlen(sendbuf), 0 ); 
			clientphase = ExitC;
			break;
				   }
		case InitialC: {
			if(localtest && recordOnly){
				createSecurityParameters();
				clientphase = RecordPrepareC;
			}
			else{
				generateClientHello(sendbuf); 
				send( ConnectSocket, sendbuf, (int)strlen(sendbuf), 0 ); 
				clientphase = HandshakeWaitServerHello;
			}
			printf("InitialC Finished\n");
			break;
					  }
		case HandshakeWaitServerHello: {
			recv(ConnectSocket, recvbuf, recvbuflen, 0);
			parseServerHello(recvbuf);
			recv(ConnectSocket, recvbuf, recvbuflen, 0);
			parseServerCertificate(recvbuf);
			recv(ConnectSocket, recvbuf, recvbuflen, 0);
			parseServerKeyExchange(recvbuf);
			recv(ConnectSocket, recvbuf, recvbuflen, 0);
			parseServerHelloDone(recvbuf);
			recv(ConnectSocket, recvbuf, recvbuflen, 0);
			generateClientKeyExchange(sendbuf);
			send(ConnectSocket, sendbuf, (int)strlen(sendbuf), 0);
			generateClientCertificateVerify(sendbuf);
			send(ConnectSocket, sendbuf, (int)strlen(sendbuf), 0);
			generateClientFinishedMessage(sendbuf);
			send(ConnectSocket, sendbuf, (int)strlen(sendbuf), 0);
			clientphase = HandshakeWaitServerFinishedMessage;
			break;
									   }
		case HandshakeWaitServerFinishedMessage: {
			recv(ConnectSocket, recvbuf, recvbuflen, 0);
			parseServerFinishedMessage(recvbuf);
			clientphase = RecordLayerC;
			break;
									   }
		case RecordPrepareC: {
			if(!localtest){
				// get security_parameters from server
			}
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

				bool valid = AEAD_Decrypt(client_write_key, nonce, plaintext.fragment, (int *)&(plaintext.length), additional_data, additional_data_len, ciphertext.fragment.content, ciphertext.length);
				printf("Plaintext Valid? %s\n", (valid) ? "true" : "false");
			}
			printf("RecordLayer Finished\n");
			clientphase = ExitC;
			break;
						  }
		case ExitC:{
			iResult = recv(ConnectSocket, recvbuf, recvbuflen, 0);
			if ( iResult > 0 ){
				printf("Bytes received: %d\n", iResult);
			}
			else if ( iResult == 0 )
				printf("Connection closed\n");
			else
				printf("recv failed with error: %d\n", WSAGetLastError());

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
