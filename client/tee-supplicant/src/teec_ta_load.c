#include <dirent.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include <teec_trace.h>
#include <teec_ta_load.h>

#ifdef CFG_TA_TEST_PATH
# ifndef TEEC_TEST_LOAD_PATH
#  ifdef __ANDROID__
#   define TEEC_TEST_LOAD_PATH "/data/vendor/tee"
#  else
#   define TEEC_TEST_LOAD_PATH "/tmp"
#  endif
# endif
#endif

#ifndef PATH_MAX
#define PATH_MAX 255
#endif

struct tee_rpc_cmd {
	void *buffer;
	uint32_t size;
	uint32_t type;
	int fd;
};

static int try_load_secure_module(const char* prefix,
		const char* dev_path, const TEEC_UUID *destination,
		void *ta, size_t *ta_size)
{
	char fname[PATH_MAX] = { 0 };
	FILE *file = NULL;
	bool first_try = true;
	size_t s = 0;
	int n = 0;

	if (!ta_size || !destination) {
		printf("wrong inparameter to TEECI_LoadSecureModule\n");
		return TA_BINARY_NOT_FOUND;
	}

again:
	n = snprintf(fname, PATH_MAX,
			"%s/%s/%08x-%04x-%04x-%02x%02x%s%02x%02x%02x%02x%02x%02x.ta",
			prefix, dev_path,
			destination->timeLow,
			destination->timeMid,
			destination->timeHiAndVersion,
			destination->clockSeqAndNode[0],
			destination->clockSeqAndNode[1],
			first_try ? "-" : "",
			destination->clockSeqAndNode[2],
			destination->clockSeqAndNode[3],
			destination->clockSeqAndNode[4],
			destination->clockSeqAndNode[5],
			destination->clockSeqAndNode[6],
			destination->clockSeqAndNode[7]);

	DMSG("Attempt to load %s", fname);

	if ((n < 0) || (n >= PATH_MAX)) {
		EMSG("wrong TA path[%s]", fname);
		return TA_BINARY_NOT_FOUND;
	}

	file = fopen(fname, "r");
	if (file == NULL) {
		DMSG("failed to open the ta %s TA-file", fname);
		if (first_try) {
			first_try = false;
			goto again;
		}
		return TA_BINARY_NOT_FOUND;
	}

	if (fseek(file, 0, SEEK_END)) {
		fclose(file);
		return TA_BINARY_NOT_FOUND;
	}

	s = ftell(file);
	if (s > *ta_size || !ta)
		goto out;

	if (fseek(file, 0, SEEK_SET)) {
		fclose(file);
		return TA_BINARY_NOT_FOUND;
	}

	if (s != fread(ta, 1, s, file)) {
		printf("error fread TA file\n");
		fclose(file);
		return TA_BINARY_NOT_FOUND;
	}

out:
	*ta_size = s;
	fclose(file);
	return TA_BINARY_FOUND;
}

int TEECI_LoadSecureModule(const char* dev_path,
		const TEEC_UUID *destination, void *ta, size_t *ta_size)
{
#ifdef TEEC_TEST_LOAD_PATH
	int res = 0;

	res = try_load_secure_module(TEEC_TEST_LOAD_PATH,
			dev_path, destination, ta, ta_size);
	if (res != TA_BINARY_NOT_FOUND)
		return res;
#endif

	return try_load_secure_module(TEEC_LOAD_PATH,
			dev_path, destination, ta, ta_size);
}
