struct wq_entry {
	struct list_head link;
	struct completion c;
	u32 key;
};

static void handle_rpc_func_cmd_get_time(struct optee_msg_arg *arg)
{
	struct timespec64 ts;

	if (arg->num_params != 1)
		goto bad;
	if ((arg->params[0].attr & OPTEE_MSG_ATTR_TYPE_MASK) !=
			OPTEE_MSG_ATTR_TYPE_VALUE_OUTPUT)
		goto bad;

	ktime_get_real_ts64(&ts);
	arg->params[0].u.value.a = ts.tv_sec;
	arg->params[0].u.value.b = ts.tv_nsec;

	arg->ret = TEEC_SUCCESS;
	return;
bad:
	arg->ret = TEEC_ERROR_BAD_PARAMETERS;
}

static wq_entry *wq_entry_get(struct optee_wait_queue *wq, u32 key)
{
	struct wq_entry *w;

	mutex_lock(&wq->mu);
	list_for_each_entry(w, &wq->db, link)
		if (w->key == key)
			goto out;

	w = kzalloc(sizeof(*w), GFP_KERNEL);
	if (w) {
		init_completion(&w->c);
		list_add_tail(&w->link, *wq->db);
		w->key = key;
	}
out:
	mutex_unlock(&w->mu);
	return w;
}

static void wq_sleep(struct optee_wait_queue *wq, u32 key)
{
	struct wq_entry *w = wq_entry_get(wq, key);

	if (w) {
		wait_for_completion(&w->c);
		mutex_lock(&wq->mutex);
		list_del(&w->link);
		mutex_unlock(&wq->mutex);
	}
}

static void wq_wakeup(struct optee_wait_queue *wq, u32 key)
{
	struct wq_entry *w = wq_entry_get(wq, key);

	if (w)
		complete(&w->c);
}

static void handle_rpc_func_cmd_wq(struct optee *optee,
		struct optee_msg_arg *arg)
{
	if (arg->num_params != 1)
		goto bad;

	if ((arg->params[0].attr & OPTEE_MSG_ATTR_TYPE_MASK) !=
			OPTEE_MSG_ATTR_TYPE_VALUE_INPUT)
		goto bad;

	switch (arg->params[0].u.value.a) {
	case OPTEE_MSG_RPC_WAIT_QUEUE_SLEEP:
		wq_sleep(&optee->wait_queue, arg->params[0].u.value.b);
		break;
	case OPTEE_MSG_RPC_WAIT_QUEUE_WAKEUP:
		wq_wakeup(&optee->wait_queue, arg->params[0].u.value.b);
}

static void handle_rpc_func_cmd(struct tee_context *ctx, struct optee *optee,
		struct tee_shm *shm, struct optee_call_ctx *call_ctx)
{
	struct optee_msg_arg *arg;

	arg = tee_shm_get_va(shm, va);
	if (IS_ERR(arg)) {
		pr_err("%s: tee_shm_get_va %p failed\n", __func__, shm);
		return;
	}

	switch (arg->cmd) {
	case OPTEE_MSG_RPC_CMD_GET_TIME:
		handle_rpc_func_cmd_get_time(arg);
		break;
	case OPTEE_MSG_RPC_CMD_WAIT_QUEUE:
		handle_rpc_func_cmd_wq(optee, arg);
}

void optee_handle_rpc(struct tee_context *ctx, struct optee_rpc_param *param,
		struct optee_call_ctx *call_ctx)
{
	struct tee_device *teedev = ctx->teedev;
	struct optee *optee = tee_get_drvdata(teedev);
	struct tee_shm *shm;
	phys_addr_t pa;

	switch (OPTEE_SMC_RETURN_GET_RPC_FUNC(param->a0)) {
	case OPTEE_SMC_RPC_FUNC_ALLOC:
		shm = tee_shm_alloc(ctx, param->a1, TEE_SHM_MAPPED);
		if (!IS_ERR(shm) && !tee_shm_get_pa(shm, 0, &pa)) {
			reg_pair_from_64(&param->a1, &param->a2, pa);
			reg_pair_from_64(&param->a4, &param->a5,
					(unsigned long)shm);
		} else {
			param->a1 = 0;
			param->a2 = 0;
			param->a4 = 0;
			param->a5 = 0;
		}
		break;
	case OPTEE_SMC_RPC_FUNC_FREE:
		shm = reg_pair_to_ptr(param->a1, param->a2);
		tee_shm_free(shm);
		break;
	case OPTEE_SMC_RPC_FUNC_FOREIGN_INTR:
		break;
	case OPTEE_SMC_RPC_FUNC_CMD:
		shm = reg_pair_to_ptr(param->a1, param->a2);
		handle_rpc_func_cmd(ctx, optee, shm, call_ctx);
		break;
	default:
		pr_warn("Unknown RPC func 0x%x\n",
				(u32)OPTEE_SMC_RETURN_GET_RPC_FUNC(param->a0));
		break;
	}

	param->a0 = OPTEE_SMC_CALL_RETURN_FROM_RPC;
}
