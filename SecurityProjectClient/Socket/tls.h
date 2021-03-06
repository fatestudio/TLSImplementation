#include <stdint.h>

#define TLSPlaintextMAXL (16384)
#define TLSCompressedMAXL (16384 + 1024)
#define NonceMAXL 12

typedef unsigned char opaque;	// how to represent uninterpreted byte?
typedef opaque * p_opaque;

typedef struct {
	int lala;
    uint32_t gmt_unix_time;
    opaque random_bytes[28];
} Random;

typedef opaque SessionID;	// what is the meaning of <0..32>?

typedef uint8_t CipherSuite[2];    /* Cryptographic suite selector */

typedef struct {
    uint8_t major;
    uint8_t minor;
} ProtocolVersion;

typedef enum { nullComp=0, comp=255 } CompressionMethod;

typedef enum { server, client } ConnectionEnd;

typedef enum { tls_prf_sha256 } PRFAlgorithm;

enum bulk_enum { nullBulk, rc4, des3, aes };
typedef bulk_enum BulkCipherAlgorithm;

typedef enum { stream, block, aead } CipherType;

typedef enum { nullMAC, hmac_md5, hmac_sha1, hmac_sha256,
           hmac_sha384, hmac_sha512, aes_128_ccm} MACAlgorithm;

typedef enum {
    change_cipher_spec = 20, alert = 21, handshake = 22,
    application_data = 23, maxTYPE = 255
} ContentType;

//client's
typedef enum {
	TestC,
	InitialC, 
	HandshakeWaitServerHello,
	HandshakeWaitServerFinished,
	HandshakeWaitServerFinishedMessage,
	RecordPrepareC,
	RecordLayerC,
	ExitC
} ClientPhase;

typedef struct {
	ProtocolVersion client_version;
    Random random;
    SessionID session_id;
    CipherSuite cipher_suites;	
    CompressionMethod compression_methods; 
} ClientHello;

typedef struct {
    ConnectionEnd          entity;
    PRFAlgorithm           prf_algorithm;
    BulkCipherAlgorithm    bulk_cipher_algorithm;
    CipherType             cipher_type;
    uint8_t                enc_key_length;
    uint8_t                block_length;
    uint8_t                fixed_iv_length;
    uint8_t                record_iv_length;
    MACAlgorithm           mac_algorithm;
    uint8_t                mac_length;
    uint8_t                mac_key_length;
    CompressionMethod      compression_algorithm;
    opaque                 master_secret[48];
    opaque                 client_random[32];
    opaque                 server_random[32];
} SecurityParameters;

typedef struct {
    ContentType type;
    ProtocolVersion version;
    uint16_t length;
    opaque fragment[TLSPlaintextMAXL]; 
} TLSPlaintext;

typedef struct {
    ContentType type;       /* same as TLSPlaintext.type */
    ProtocolVersion version;/* same as TLSPlaintext.version */
    uint16_t length;
    opaque fragment[TLSCompressedMAXL];
} TLSCompressed;

typedef struct {
    uint32_t write_IV;  // low order 32-bits
    uint64_t seq_num;
} CCMNonce;

typedef struct {
    uint64_t nonce_explicit;
    opaque content[TLSCompressedMAXL];
} GenericAEADCipher;

typedef struct {
    ContentType type;
    ProtocolVersion version;
    uint16_t length;
    GenericAEADCipher fragment; // ignored stream and block ciphers
} TLSCiphertext;