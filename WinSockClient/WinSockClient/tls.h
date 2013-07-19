typedef enum { AES_128_CCM, AES_256_CCM } Algorithm;

typedef enum { null=0, comp=255 } Compress;

typedef struct {
	Algorithm ag;
	Compress comp;
} Status;

typedef struct {
	char *buf;
	int buf_len;
} StringBuffer;