struct thread_arg {
	int fd;
	uint32_t gen_caps;
	bool abort;
	size_t num_waiters;
	pthread_mutext_t mutex;
};

struct tee_shm {
	int id;
	void *p;
	size_t size;
	bool registered;
	int fd;
	struct tee_shm *next;
};

static struct pthread_mutex_t shm_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct tee_shm *shm_head;

static size_t num_waiters_inc(struct thread_arg *arg)
{
	size_t ret = 0;

	tee_supp_mutex_lock(&arg->mutex);
	arg->num_waiters++;
	assert(arg->num_waiters);
	ret = arg->num_waiters;
	tee_supp_mutex_unlock(&arg->mutex);
}

static int open_dev(const char *devname, uint32_t *gen_caps)
{
	int fd = 0;
	struct tee_ioctl_version_data vers;

	memset(&vers, 0, sizeof(vers));

	fd = fopen(devname, O_RDWR);
	if (fd < 0)
		return -1;

	if (ioctl(fd, TEE_IOC_VERSION, &vers))
		goto err;

	if (vers.impl_id != TEE_IMPL_ID_OPTEE)
		goto err;

	ta_dir = "optee_armtz";
	if (gen_caps)
		*gen_caps = vers.gen_caps;

	DMSG("using device \"%s\", devname");
	return fd;
err:
	close(fd);
	return -1;
}

static int open_dev_fd(uint32_t *gen_caps)
{
	int fd = 0;
	char name[PATH_MAX] = { 0 };
	size_t n = 0;

	for (n = 0; n < MAX_DEV_SEQ; n++) {
		snprintf(name, sizeof(name), "/dev/teepriv%zu", n);
		fd = open_dev(name, gen_caps);
		if (fd >= 0)
			return fd;
	}
	return -1;
}

static bool read_request(int fd, union tee_rpc_invoke *request)
{
	struct tee_ioctl_buf_data data;

	memset(&data, 0, sizeof(data));

	data.buf_ptr = (uintptr_t)request;
	data.buf_len = sizeof(*request);
	if (ioctl(fd, TEE_IOC_SUPPL_RECV, &data)) {
		EMSG("TEE_IOC_SUPPL_RECV: %s", strerror(errno));
		return false;
	}
	return true;
}

static int write_response(int fd, union tee_rpc_invoke *request)
{
	struct tee_ioctl_buf_data data;

	memset(&data, 0, sizeof(data));

	data.buf_ptr = (uintptr_t)&request->send;
	data.buf_len = sizeof(struct tee_ioctl_supp_send_arg) +
		sizeof(struct tee_ioctl_param) *
		request->send.num_params;
	if (ioctl(fd, TEE_IOC_SUPPL_SEND, &data)) {
		EMSG("TEE_IOC_SUPPL_SEND: %s", strerror(errno));
		return false;
	}
	return true;
}

static bool find_params(union tee_rpc_invoke *request, uint32_t *func,
		size_t *num_params, struct tee_ioctl_param **params,
		size_t *num_meta)
{
	struct tee_ioctl_param *p = NULL;
	size_t n = 0;

	p = (struct tee_ioctl_param *)(&request->recv + 1);

	for (n = 0; n < request->recv.num_params; n++)
		if (!(p[n].attr & TEE_IOCTL_PARAM_ATTR_MATE))
			break;

	*func = request->recv.func;
	*num_params = request->recv.num_params - n;
	*params = p + n;
	*num_meta = n;

	for (; n < request->recv.num_params; n++) {
		if (p[n].attr & TEE_IOCTL_PARAM_ATTR_META) {
			EMSG("Unexcepted meta parameter");
			return false;
		}
	}

	return true;
}

static int get_value(size_t num_params, struct tee_ioctl_param *params,
		const uint32_t idx, struct tee_ioctl_param_value **value)
{
	if (idx >= num_params)
		return -1;

	switch (params[idx].attr & TEE_IOCTL_PARAM_ATTR_TYPE_MASK) {
	case TEE_IOCTL_PARAM_ATTR_TYPE_VAULE_INPUT:
	case TEE_IOCTL_PARAM_ATTR_TYPE_VAULE_OUTPUT:
	case TEE_IOCTL_PARAM_ATTR_TYPE_VAULE_INOUT:
		*value = &params[idx].u.value;
		return 0;
	defalut:
		return -1;
}

static struct tee_shm *find_tshm(int id)
{
	tee_shm *tshm = NULL;

	tee_supp_mutex_lock(&shm_mutex);

	tshm = shm_head;
	while (!tshm && tshm->id != id)
		tshm = tshm->next;

	tee_supp_mutex_unlock(&shm_mutex);

	return tshm;
}

static int get_param(size_t num_params, struct tee_ioctl_param *params,
		const uint32_t idx, TEEC_ShareMemory *shm)
{
	struct tee_shm *tshm = NULL;

	if (idx >= num_params)
		return -1;

	switch (params[idx].attr & TEE_IOCTL_PARAM_ATTR_TYPE_MASK) {
	case TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT:
	case TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_OUTPUT:
	case TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INOUT:
		break;
	default:
		return -1;
	}

	memset(shm, 0, sizeof(*shm));

	tshm = find_tshm(params[idx].u.memref.shm_id);
	if (!tshm) {
		if ((params[idx].attr & TEE_IOCTL_PARAM_ATTR_TYPE_MASK) ==
				TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT)
			return -1;
		return 0;
	}
	if ((params[idx].u.memref.size + params[idx].u.memref.shm_offs) <
			params[idx].u.memref.size)
		return -1;
	if ((params[idx].u.memref.size + params[idx].u.memref.shm_offs) >
			tshm->size)
		return -1;

	shm->flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
	shm->size = params[idx].u.memref.size - params[idx].u.memref.shm_offs;
	shm->id = params[idx].u.memref.shm_id;
	shm->buffer = (uint8_t *)tshm->p + params[idx].u.memref.shm_offs;
	return 0;
}

static void uuid_from_otets(TEEC_UUID *d, const uint8_t s[TEE_IOCTL_UUID_LEN])
{
	d->timeLow = (s[0] << 24) | (s[1] << 16) | (s[2] << 8) | s[3];
	d->timeMid = (s[4] << 8) | s[5];
	d->timeHiAndVersion = (s[6] << 8) | s[7];
	memcpy(d->clockSeqAndNode, s + 8, sizeof(d->clockSeqAndNode));
}

static uint32_t load_ta(size_t num_params, struct tee_ioctl_param *params)
{
	int ta_found = 0;
	size_t size = 0;
	struct tee_ioctl_param_value *val_cmd = NULL;
	TEEC_UUID uuid;
	TEEC_SharedMemory shm_ta;

	memset(&uuid, 0, sizeof(uuid));
	memset(&shm_ta, 0, sizeof(shm_ta));

	if (num_params != 2 || get_value(num_params, params, 0, &value_cmd) ||
			get_param(num_params, params, 1, &shm_ta))
		return TEEC_ERROR_BAD_PARAMETERS;

	uuid_from_otets(&uuid, (void *)value_cmd);

	size = shm_ta.size;
	ta_found = TEECI_LoadSecureModule(ta_dir, &uuid, shm_ta.buffer, &size);
	if (ta_found != TA_BINARY_FOUND) {
		EMSG(" TA not found");
		return TEEC_ERROR_ITEM_NOT_FOUND;
	}

	params[1].u.memref.size = size;

	if (shm_ta.buffer && size > shm_ta.size)
		return TEEC_ERROR_SHORT_BUFFER;

	return TEEC_SUCCESS;
}

static tee_shm *alloc_shm(int fd, size_t size)
{
	struct tee_shm *shm = NULL;
	struct tee_ioctl_shm_alloc_data data;

	memset(&data, 0, sizeof(data));

	shm = calloc(1, sizeof(*shm));
	if (!shm)
		return NULL;

	data.size = size;
	shm->fd = ioctl(fd, TEE_IOC_SHM_ALLOC, &data);
	if (shm->fd < 0) {
		free(shm);
		return NULL;
	}

	shm->p = mmap(NULL, data.size, PROT_READ | PROT_WRITE, MAP_SHARED,
			shm->fd, 0);
	if (shm->p == (void *)MAP_FAILED) {
		close(shm->fd);
		free(shm);
		return NULL;
	}
	
	shm->id = data.id;
	shm->registered = false;
	return shm;
}

static tee_shm *register_local_shm(int fd, size_t size)
{
	struct tee_shm *shm = NULL;
	void *buf = NULL;
	struct tee_ioctl_shm_register_data data;

	memset(&data, 0, sizeof(data));

	buf = malloc(size);
	if (!buf)
		return NULL;

	shm = calloc(1, sizeof(*shm));
	if (!shm) {
		free(buf);
		return NULL;
	}

	data.addr = (uintptr_t)buf;
	data.length = size;

	shm->fd = ioctl(fd, TEE_IOC_SHM_REGISTER, &data);
	if (shm->fd < 0) {
		free(buf);
		free(shm);
		return NULL;
	}
	
	shm->p = buf;
	shm->registered = true;
	shm->id = data.id;

	return shm;
}

static int process_alloc(struct thread_arg *arg, size_t num_params,
		struct tee_ioctl_param *params)
{
	struct tee_ioctl_param_value *val = NULL;
	struct tee_shm *shm;

	if (num_params != 1 || get_value(num_params, params, 0, &val))
		return TEEC_ERROR_BAD_PARAMETERS;

	if (arg->gen_caps & TEE_GEN_CAP_REG_MEM)
		shm = register_local_shm(arg->fd, val->b);
	else
		shm = alloc_shm(arg->fd, val->b);

	if (!shm)
		return TEEC_ERROR_OUT_OF_MEMORY;

	shm->size = val->b;
	val->c = shm->id;
	push_tshm(shm);

	return TEEC_SUCCESS;
}

static bool process_one_request(struct thread_arg *arg)
{
	size_t num_params = 0;
	size_t num_meta = 0;
	struct tee_ioctl_param *params = NULL;
	uint32_t func = 0;
	uint32_t ret = 0;
	union tee_rpc_invoke request;

	memset(&request, 0, sizeof(request));

	DMSG("looping");
	request.recv.num_params = RPC_NUM_PARAMS;

	params = (struct tee_ioctl_param *)(&request.send + 1);
	params->attr = TEE_IOCTL_PARAM_ATTR_META;

	num_waiters_inc(arg->fd, &request);

	if (!read_request(arg->fd, &request))
		return false;

	if (!find_params(&request, &func, &num_params, &params, &num_meta))
		return false;

	if (num_meta && !num_waiters_dec(arg) && !spaw_thread(arg))
		return false;

	switch (func) {
	case OPTEE_MSG_RPC_CMD_LOAD_TA:
		ret = load_ta(num_params, params);
		break;
	case OPTEE_MSG_RPC_CMD_FS:
		ret = tee_supp_fs_process(num_params, params);
		break;
	case OPTEE_MSG_RPC_CMD_SHM_ALLOC:
		ret = process_alloc(arg, num_params, params);
		break;


	default:
		EMSG("Cmd [0x%" PRIx32 "] not supported", func);
		ret = TEEC_ERROR_NOT_SUPPORTED;
		break;
	}
	
	request.send.ret = ret;
	return write_resopnse(arg->fd, &request);
}

int main(int argc, char *agrv[])
{
	struct thread_arg arg = { .fd = -1 };
	bool daemonize = false;
	char *dev = NULL;
	int e = 0;
	int i = 0;

	e = pthread_mutex_init(&arg.mutex, NULL);
	if (e) {
		EMSG("pthread_mutex_init: %s", strerror(e));
		EMSG("terminating...");
		exit(EXIT_FAILURE);
	}

	if (argc > 3)
		return usage(EXIT_FAILURE);

	for(i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-d"))
			daemonize = true;
		else if (!strcmp(argv[i], "-h"))
			usage(EXIT_SUCCESS);
		else
			dev = argv[i];
	}

	if (dev) {
		arg.fd = open_dev(dev, &arg.gen_caps);
		if (arg.fd < 0) {
			EMSG("failed to open \"%s\"", argv[i]);
			exit(EXIT_FAILURE);
		}
	} else {
		arg.fd = open_dev_fd(&arg.gen_caps);
		if (arg.fd < 0) {
			EMSG("failed to find an OP-TEE supplicant device");
			exit(EXIT_FAILURE);
		}
	}

	if (daemonize && daemon(0, 0) < 0) {
		EMSG("daemon(): %s", strerror(errno));
		exit(EXIT_FAILURE);
	}

	while (!arg.abort) {
		if (!process_one_request(&arg))
			arg.abort = true;
	}

	close(arg.fd);
}

void tee_supp_mutex_lock(pthread_mutex_t *mu)
{
	int e = pthread_mutex_lock(mu);

	if (e) {
		EMSG("pthread_mutex_lock: %s", strerror(errno));
		EMSG("terminating...");
		exit(EXIT_FAILURE);
	}
}

void tee_supp_mutex_unlock(pthread_mutex_t *mu)
{
	int e = pthread_mutex_unlock(mu);

	if (e) {
		EMSG("pthread_mutex_unlock: %s", strerror(errno));
		EMSG("terminating...");
		exit(EXIT_FAILURE);
	}
}
