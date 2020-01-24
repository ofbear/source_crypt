#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

#include "source_crypt.h"

SourceSystemBuffer sys_buffer;
SourceCryptBuffer pl_buffer;

int main(int argc, char *argv[])
{
	struct stat stat_in, stat_out;

	// arg check
	if (argc < 3) {
		printf("%s:%s\n", __func__, "arg check");
		return 1;
	}
	// input open check
	if (stat(argv[2], &stat_in) != 0) {
		printf("%s:%s\n", __func__, "input open check");
		return 1;
	}
	// output open check
	int check = stat(argv[3], &stat_out);
	if (stat(argv[3], &stat_out) != 0) {
		printf("%s:%s\n", __func__, "output open check");
		return 1;
	}
	// output path dir check
	if (!S_ISDIR(stat_out.st_mode)) {
		printf("%s:%s\n", __func__, "output path dir check");
		return 1;
	}

	// sys init
	source_sys_init();

	// arg setting
	sys_buffer.mode = argv[1];
	sys_buffer.in_dir = argv[2];
	sys_buffer.out_dir = argv[3];

	// add '/' to output dir
	if (sys_buffer.out_dir[strlen(sys_buffer.out_dir) - 1] != '/') {
		strcat(sys_buffer.out_dir, "/");
	}

	// input directory root
	if (S_ISDIR(stat_in.st_mode)) {
		source_dir(sys_buffer.in_dir);
	}

	// input file root
	else if (S_ISREG(stat_in.st_mode)) {
		sys_buffer.in_file = sys_buffer.in_dir;
		sys_buffer.in_dir = calloc(1, sizeof(char) * PATH_SIZE);
		strncpy(sys_buffer.in_dir, sys_buffer.in_file, (unsigned char*)strrchr(sys_buffer.in_file, (int)('/')) - sys_buffer.in_file + 1);

		source_file(sys_buffer.in_file);

		free(sys_buffer.in_dir);
	}

	// init
	source_sys_init();
}

// init sys
void source_sys_init()
{
	memset(&sys_buffer, 0x00, sizeof(SourceSystemBuffer));
}

// directory root
void source_dir(unsigned char *in_dir)
{
	DIR *p_dir;
	struct dirent *dp;
	struct stat stat_chk;
	unsigned char path[PATH_SIZE];
	unsigned char *path_buf;
	unsigned char name_dir[PATH_SIZE];

	// open dir
	p_dir = opendir(in_dir);
	for (dp = readdir(p_dir); dp != NULL; dp = readdir(p_dir)) {
		if (dp->d_name[0] != '.') {
			// make filename
			memset(&path , 0x00 , sizeof(char) * PATH_SIZE);
			snprintf(path, PATH_SIZE, "%s%s", in_dir, dp->d_name);

			stat(path, &stat_chk);

			// directory root
			if (S_ISDIR(stat_chk.st_mode)) {
				// add '/' to output path
				if (path[strlen(path)-1] != '/') {
					strcat(path, "/");
				}

				// make output directory
				snprintf(name_dir, PATH_SIZE, "%s%s", sys_buffer.out_dir, path + strlen(sys_buffer.in_dir));
				mkdir(name_dir, 0755);

				source_dir(path);
			}

			// file root
			else if (S_ISREG(stat_chk.st_mode)) {
				if(strstr(path, ".php") != NULL) {
					source_file(path);
				}
			}
		}
	}

	// close directory
	closedir(p_dir);

	return;
}

// file root
void source_file(unsigned char *in_file)
{
	unsigned char *tmp_file;

	// init
	source_pl_init();

	// open check
	pl_buffer.fp_r = fopen(in_file, "r");
	if (!pl_buffer.fp_r) {
		printf("%s:%s\n", __func__, "open check");
		return;
	}

	pl_buffer.path = calloc(1, sizeof(char) * PATH_SIZE);

	// make name path(output dir + (fullpath - input dir))
	// ex) 
	// input dir:/opt/source/apps/lib/
	// fullpath:/opt/source/apps/lib/auth/target.php
	// -> auth/target.php
	// output dir:/usr/local/src/enc/
	// -> /usr/local/src/enc/auth/target.php
	tmp_file = in_file + strlen(sys_buffer.in_dir);
	snprintf(pl_buffer.path, PATH_SIZE, "%s/%s", sys_buffer.out_dir, tmp_file);

	// encrypt
	if (strcmp((const char *)sys_buffer.mode, "encrypt") == 0) {
		source_encrypt();

	// decrypt
	} else if (strcmp((const char *)sys_buffer.mode, "decrypt") == 0) {
		source_decrypt();
	}

	// init
	source_pl_init();
}

// init
void source_pl_init()
{
	if (pl_buffer.path != 0) {
		free(pl_buffer.path);
	}
	if (pl_buffer.fp_r != 0) {
		fclose(pl_buffer.fp_r);
	}
	if (pl_buffer.fp_w != 0) {
		fclose(pl_buffer.fp_w);
	}
	if (pl_buffer.data_raw != 0) {
		free(pl_buffer.data_raw);
	}
	if (pl_buffer.data_tmp != 0) {
		free(pl_buffer.data_tmp);
	}
	if (pl_buffer.data_enc != 0) {
		free(pl_buffer.data_enc);
	}

	memset(&pl_buffer, 0x00, sizeof(SourceCryptBuffer));
}

// encrypt wrapper
void source_encrypt()
{
	struct stat stat_buf;
	int ret = ERR_NOTHING;

	// get file data
	fstat(fileno(pl_buffer.fp_r), &stat_buf);
	pl_buffer.len_tmp = stat_buf.st_size + 1;
	pl_buffer.data_tmp = calloc(1, sizeof(char) * pl_buffer.len_tmp);
	fread(pl_buffer.data_tmp, pl_buffer.len_tmp, 1, pl_buffer.fp_r);

	// add tag(tag is checked on decrypt)
	pl_buffer.len_raw = pl_buffer.len_tmp + (int)strlen(PL_TOOL_NAME);
	pl_buffer.data_raw = calloc(1, sizeof(char) * pl_buffer.len_raw);
	snprintf(pl_buffer.data_raw, pl_buffer.len_raw, "%s%s", PL_TOOL_NAME, pl_buffer.data_tmp);

	// prepare memory for encrypt data
	pl_buffer.len_enc = ((pl_buffer.len_raw / PL_ENCRYPT_BLOCK_SIZE) + 1) * PL_ENCRYPT_BLOCK_SIZE;
	pl_buffer.data_enc = calloc(1, sizeof(char) * pl_buffer.len_enc);

	// encrypt
	if ((ret = source_encrypt_openssl(pl_buffer.data_raw, pl_buffer.len_raw, pl_buffer.data_enc, &pl_buffer.len_enc)) != ERR_NOTHING) {
		printf("%s:%s:%d\n", __func__, "encrypt", ret);
		return;
	}

	// write encrypt data
	pl_buffer.fp_w = fopen(pl_buffer.path, "w");
	fwrite(pl_buffer.data_enc, pl_buffer.len_enc, 1, pl_buffer.fp_w);
}

// decrypt wrapper
void source_decrypt()
{
	struct stat stat_buf;
	int ret = ERR_NOTHING;

	// get file data
	fstat(fileno(pl_buffer.fp_r), &stat_buf);
	pl_buffer.len_enc = stat_buf.st_size;
	pl_buffer.data_enc = calloc(1, sizeof(char) * pl_buffer.len_enc);
	fread(pl_buffer.data_enc, pl_buffer.len_enc, 1, pl_buffer.fp_r);

	// prepare memory for decrypt data
	pl_buffer.len_raw = pl_buffer.len_enc;
	pl_buffer.data_raw = calloc(1, sizeof(char) * pl_buffer.len_raw);

	// decrypt
	if ((ret = source_decrypt_openssl(pl_buffer.data_enc, pl_buffer.len_enc, pl_buffer.data_raw, &pl_buffer.len_raw)) != ERR_NOTHING) {
		printf("%s:%s:%d\n", __func__, "decrypt", ret);
		return;
	}

	// tag check
	if (strstr((const char *)pl_buffer.data_raw, PL_TOOL_NAME) == 0) {
		printf("%s:%s\n", __func__, "tag check");
		return;
	}

	// write decrypt data
	pl_buffer.fp_w = fopen(pl_buffer.path, "w");
	fwrite(pl_buffer.data_raw, pl_buffer.len_raw, 1, pl_buffer.fp_w);
}

// encrypt
int source_encrypt_openssl(const char* data_raw, const int len_raw, unsigned char* data_enc, int *len_enc)
{
	EVP_CIPHER_CTX *ctx;
	int len_enc_0 = 0;
	int len_enc_1 = 0;

	// new
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        EVP_CIPHER_CTX_free(ctx);
        return EVP_FAIL_EVP_NEW;
    }

	// init
	// if you want to change encrypt method, you change "EVP_aes_256_cbc"
	// https://www.openssl.org/docs/man1.1.0/crypto/EVP_aes_256_cbc.html
	if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, PL_DEFAULT_CRYPTKEY, PL_INITIAL_VECTOR)) {
		EVP_CIPHER_CTX_free(ctx);
		return ERR_FAIL_EVP_INIT;
	}

	// Execute
	if (!EVP_EncryptUpdate(ctx, data_enc, &len_enc_0, (unsigned char *)data_raw, len_raw)) {
		EVP_CIPHER_CTX_free(ctx);
		return ERR_FAIL_EVP_UPDATE;
	}

	// padding
	if (!EVP_EncryptFinal_ex(ctx, (unsigned char *)(data_enc + len_enc_0), &len_enc_1)) {
		EVP_CIPHER_CTX_free(ctx);
		return ERR_FAIL_EVP_FINAL;
	}

	*len_enc = len_enc_0 + len_enc_1;

	EVP_CIPHER_CTX_free(ctx);

	return ERR_NOTHING;
}

// decrypt
int source_decrypt_openssl(const unsigned char* data_enc, const int len_enc, char* data_raw, int *len_raw)
{
	EVP_CIPHER_CTX *ctx;
	int len_raw_0 = 0;
	int len_raw_1 = 0;

	// new
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        EVP_CIPHER_CTX_free(ctx);
        return EVP_FAIL_EVP_NEW;
    }

	// init
	// if you want to change encrypt method, you change "EVP_aes_256_cbc"
	// https://www.openssl.org/docs/man1.1.0/crypto/EVP_aes_256_cbc.html
	if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, PL_DEFAULT_CRYPTKEY, PL_INITIAL_VECTOR)) {
		EVP_CIPHER_CTX_free(ctx);
		return ERR_FAIL_EVP_INIT;
	}

	// Execute
	if (!EVP_DecryptUpdate(ctx, (unsigned char *)data_raw, &len_raw_0, data_enc, len_enc)) {
		EVP_CIPHER_CTX_free(ctx);
		return ERR_FAIL_EVP_UPDATE;
	}

	// padding
	if (!EVP_DecryptFinal_ex(ctx, (unsigned char *)(data_raw + len_raw_0), &len_raw_1)) {
		EVP_CIPHER_CTX_free(ctx);
		return ERR_FAIL_EVP_FINAL;
	}

	*len_raw = len_raw_0 + len_raw_1 - 1;
	memset(data_raw + *len_raw, 0x00, len_enc - *len_raw);

	EVP_CIPHER_CTX_free(ctx);

	return ERR_NOTHING;
}

