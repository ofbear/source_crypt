#define PATH_SIZE	(128)

static const int PL_ENCRYPT_BLOCK_SIZE				= 16;
static const unsigned char PL_INITIAL_VECTOR[]		= "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345";	// change ok
static const unsigned char PL_DEFAULT_CRYPTKEY[]	= "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345";	// change ok
static const unsigned char PL_TOOL_NAME[]			= "<?php /* SOURCE_GUARD */ ?>";

enum {
	ERR_NOTHING = 0,
	ERR_NOT_ENCRYPT,
	ERR_NOT_SOURCE_GUARD,
	EVP_FAIL_EVP_NEW,
	ERR_FAIL_EVP_INIT,
	ERR_FAIL_EVP_UPDATE,
	ERR_FAIL_EVP_FINAL,
};

typedef struct {
	char *mode;

	unsigned char *in_dir;
	unsigned char *out_dir;

	unsigned char *in_file;
	unsigned char *out_file;

} SourceSystemBuffer;

typedef struct {
	FILE *fp_r;
	FILE *fp_w;

	char *data_raw;
	char *data_tmp;
	char *data_enc;

	int* len_raw;
	int len_tmp;
	int* len_enc;

} SourceCryptBuffer;

int main(int argc, char *argv[]);
void source_sys_init();
void source_dir(unsigned char *in_dir);
void source_file(unsigned char *in_file);
void source_pl_init();
void source_encrypt();
void source_decrypt();
int source_encrypt_openssl(const char* data_raw, const int len_raw, unsigned char* data_enc, int *len_enc);
int source_decrypt_openssl(const unsigned char* data_enc, const int len_enc, char* data_raw, int *len_raw);

