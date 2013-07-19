//for hello
typedef unsigned char uint8;
typedef uint8 uint32[4];
typedef unsigned char opaque;	// how to represent uninterpreted byte?

typedef struct {
    uint32 gmt_unix_time;
    opaque random_bytes[28];
} Random;

typedef opaque SessionID;	// what is the meaning of <0..32>?

typedef uint8 CipherSuite[2];    /* Cryptographic suite selector */

typedef enum { Null = (0), Compress = (255) } CompressionMethod;

typedef struct {
    uint8 major;
    uint8 minor;
} ProtocolVersion;

//client's
typedef enum {
	Test,
	Initial, 
	HandshakeWaitServerHello,
	HandshakeWaitServerFinished,

	Exit
} ClientPhase;

struct {
	ProtocolVersion client_version;
    Random random;
    SessionID session_id;
    CipherSuite cipher_suites;	// <2..2^16-2> I believe it means the value threshold
    CompressionMethod compression_methods; //<1..2^8-1>
//    select (extensions_present) {
//        case false:
//           struct {};
//        case true:
//            Extension extensions<0..2^16-1>;
//    };
} ClientHello;


//server's
typedef enum {
	TestS,
	InitialS, 
	HandshakeWaitClientKeyExchange,
	RecordLayer,
	ExitS
} ServerPhase;

typedef struct {
    ProtocolVersion server_version;
    Random random;
    SessionID session_id;
    CipherSuite cipher_suite;
    CompressionMethod compression_method;
} ServerHello;
