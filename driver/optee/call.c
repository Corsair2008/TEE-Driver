struct optee_call_waiter {
	struct list_head list_node;
	struct completion c;
};

static void optee_cq_wait_init(struct optee_call_queue *cq,
		struct optee_call_waiter *w)
{
	mutex_lock(&cq->mutex);
	init_completion(&w->c);
	list_add_tail(&w->list_node, &cq->waiters);
	mutex_unlock(&cq->mutex);
}

static void optee_cq_wait_for_completion(struct optee_call_queue *cq,
		struct optee_call_waiter *w)
{
	wait_for_completion(&w->c);

	mutex_lock(&cq->mutex);
	list_del(&w->list_node);
	reinit_completion(&w->c);
	list_add_tail(&w->list_node, &cq->waiters);
	mutex_unlock(&cq->mutex);
}

static optee_cq_complete_one(struct optee_call_queue *cq)
{
	struct optee_call_waiter *w;

	list_for_eatch_entry(w, &cq->waiters, list_node) {
		if (!completion_done(&w->c)) {
			complete(&w->c);
			break;
		}
	}
}

static void optee_cq_wait_final(struct optee_call_queue *cq,
		struct optee_call_waiter *w)
{
	mutex_lock(&cq->mutex);
	list_del(&w->list_node);
	optee_cq_complete_one(cq);
	if (completion_done(&w->c))
		optee_cq_complete_one(cq);
	mutex_unlock(&cq->mutex);
}

u32 optee_do_call_with_arg(struct tee_context *ctx, phys_addr_t parg)
{
	struct optee *optee tee_get_drvdata(ctx->teedev);
	struct optee_call_waiter w;
	struct optee_rpc_param param = { };
	struct optee_call_ctx call_ctx = { };
	u32 ret;

	param.a0 = OPTEE_SMC_CALL_WITH_ARG;
	reg_pair_from_64(&param.a1, &param.a2, parg);
	optee_cq_wait_init(&optee->call_queue, &w);
	while (true) {
		struct arm_smccc_res res;

		optee->invoke_fn(param.a0, param.a1, param.a2, param.a3,
				param.a4, param.a5, param.a6, param.a7, &res);

		if (res.a0 == OPTEE_SMC_RETURN_ETHREAD_LIMIT) {
			optee_cq_wait_for_completion(&optee->call_queue, &w);
		} else if (OPTEE_SMC_RETURN_IS_RPC(res.a0)) {
			param.a0 = res.a0;
			param.a1 = res.a1;
			param.a2 = res.a2;
			param.a3 = res.a3;
			optee_handle_rpc(ctx, &param, &call_ctx);
		} else {
			ret = res.a0;
			break;
		}
	}

	optee_rpc_finalize_call(&call_ctx);
	optee_cq_wait_final(&optee->call_queue, &w);

	return ret;
}

static tee_shm *get_msg_arg(struct tee_context *ctx, size_t num_params,
		struct optee_msg_arg **msg_arg, phys_addr_t *msg_parg)
{
	int rc;
	struct tee_shm *shm;
	struct optee_msg_arg *ma;

	shm = tee_shm_alloc(ctx, OPTEE_MSG_GET_ARG_SIZE(num_params),
			TEE_SHM_MAPPED);
	if (IS_ERR(shm))
		return shm;

	ma = tee_shm_get_va(shm, 0);
	if (IS_ERR(ma)) {
		rc = PTR_ERR(MA);
		goto out;
	}

	rc = tee_shm_get_pa(shm, 0, msg_parg);
	if (rc)
		goto out;

	memset(ma, 0, OPTEE_MSG_GET_ARG_SIZE(num_params));
	ma->num_params = num_params;
	*msg_arg = ma;
out:
	if (rc) {
		tee_shm_free(shm);
		return ERR_PTR(rc);
	}

	return shm;
}

static int to_msg_param_tmp_mem(struct optee_msg_param *mp,
		const struct tee_param *p)
{
	int rc;
	phys_addr_t pa;

	mp->attr = OPTEE_MSG_ATTR_TYPE_TMEM_INPUT + p->attr -
		TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT;

	mp->u.tmem.shm_ref = (unsigned long)p->u.memref.shm;
	mp->u.tmem.size = p->u.memref.size;

	if (!p->u.memref.shm) {
		mp->u.tmem.buf_ptr = 0;
		return 0;
	}

	rc = tee_shm_get_pa(p->u.memref.shm, p->u.memref.shm_offs, &pa);
	if (rc)
		return rc;

	mp->u.tmem.buf_ptr = pa;
	mp->attr |= OPTEE_MSG_ATTR_CACHE_PREDEFINED <<
		OPTEE_MSG_ATTR_CACHE_SHIFT;

	return 0;
}

static int to_msg_param_reg_mem(struct optee_msg_param *mp,
		const struct tee_param *p)
{
	mp->attr = OPTEE_MSG_ATTR_PARAM_RMEM_INPUT + p->attr -
		TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT;

	mp->u.rmem.shm_ref = p->u.memref.shm;
	mp->u.rmem.size = p->u.memref.size;
	mp->u.rmem.offs = p->u.memref.shm_offs;
	return 0;
}

int optee_to_msg_param(struct optee_msg_param *msg_param, size_t num_params,
		const struct tee_param *param)
{
	int rc;
	size_t n;

	for (n = 0; n < num_params; n++) {
		struct optee_msg_param *mp = msg_param + n;
		const struct tee_param *p = param + n;

		switch (p->attr) {
		case TEE_IOCTL_PARAM_ATTR_TYPE_NONE:
			mp->attr = p->attr;
			memset(&mp->u, 0, sizeof(mp->u));
			break;
		case TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT:
		case TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_OUTPUT:
		case TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INOUT:
			mp->attr = OPTEE_MSG_ATTR_TYPE_VALUE_INPUT + p->attr -
				TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT;
			mp->u.value.a = p->u.value.a;
			mp->u.value.b = p->u.value.b;
			mp->u.value.c = p->u.value.c;
			break;
		case TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT:
		case TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_OUTPUT:
		case TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INOUT:
			if (tee_shm_is_registered(p->u.memref.shm))
				rc = to_msg_param_reg_mem(mp, p);
			else
				rc = to_msg_param_tmp_mem(mp, p);
			if (rc)
				return rc;
			break;
		default:
			return -EINVAL;
		}
	}
	return 0;
}

static int optee_from_msg_param(struct tee_param *params, size_t num_params,
		const struct optee_msg_param *msg_params)
{
	int rc;
	size_t n;
	struct tee_shm *shm;
	phys_addr_t pa;

	for (n = 0; n < num_params; n++) {
		struct tee_param *p = params + n;
		const struct optee_msg_param *mp = msg_param + n;
		u32 attr = mp->attr & OPTEE_MSG_ATTR_TYPE_MASK;

		switch (attr) {
		case OPTEE_MSG_ATTR_TYPE_NONE:
			p->attr = TEE_IOCTL_PARAM_ATTR_TYPE_NONE;
			memset(&p->u, 0, sizeof(p->u));
			break;
		case OPTEE_MSG_ATTR_TYPE_VALUE_INPUT:
		case OPTEE_MSG_ATTR_TYPE_VALUE_OUTPUT:
		case OPTEE_MSG_ATTR_TYPE_VALUE_INOUT:
			p->attr = TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT + attr -
				OPTEE_MSG_ATTR_TYPE_VALUE_INPUT;
			p->u.value.a = mp->u.value.a;
			p->u.value.b = mp->u.value.b;
			p->u.value.c = mp->u.value.c;
			break;
		case OPTEE_MSG_ATTR_TYPE_TMEM_INPUT:
		case OPTEE_MSG_ATTR_TYPE_TMEM_OUTPUT:
		case OPTEE_MSG_ATTR_TYPE_TMEM_INOUT:
			p->attr = TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT + attr -
				OPTEE_MSG_ATTR_TYPE_MEMREF_INPUT;
			p->u.memref.size = mp->u.tmem.size;
			shm = (struct tee_shm *)(unsigned long)
				mp->u.tmem.shm_ref;
			if (!shm) {
				p->u.memref.shm_offs = 0;
				p->u.memref.shm = NULL;
				break;
			}
			rc = tee_shm_get_pa(shm, 0, &pa);
			if (rc)
				return rc;
			p->u.memref.shm_offs = mp->u.tmem.buf_ptr - pa;
			p->u.memref.shm = shm;

			if (p->u.memref.size) {
				size_t o = p->memref.shm_offs + p->u.memref.size - 1;

				rc = tee_shm_get_pa(shm, o, NULL);
				if (rc)
					return rc;
			}
			break;
		case OPTEE_MSG_ATTR_TYPE_PARAM_INPUT:
		case OPTEE_MSG_ATTR_TYPE_PARAM_OUTPUT:
		case OPTEE_MSG_ATTR_TYPE_PARAM_INOUT:
			p->attr = TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT + attr -
				OPTEE_MSG_ATTR_TYPE_RMEM_INPUT;
			p->u.memref.size = mp->u.rmem.size;

			shm = (struct tee_shm *)(unsigned long)
				mp->u.rmem.shm_ref;
			if (!shm) {
				p->u.memref.shm_offs = 0;
				p->u.memref.shm = NULL;
			} else {
				p->u.memref.shm_offs = mp->u.rmem.offs;
				p->u.memref.shm = shm;
			}
			break;
		default:
			return -EINVAL;
		}
	}
	return 0;
}

int optee_open_session(struct tee_context *ctx,
		struct tee_ioctl_optee_session_arg *arg,
		struct tee_param *param)
{
	struct optee_context_data *ctxdata = ctx->data;
	int rc;
	struct tee_shm *shm;
	struct optee_msg_parg *msg_arg;
	phys_addr_t msg_parg;
	struct optee_session *sess = NULL;

	shm = get_msg_arg(ctx, arg->num_params + 2, &msg_arg, &msg_parg);
	if (IS_ERR(shm))
		return PTR_ERR(shm);

	msg_arg->cmd = OPTEE_MSG_CMD_OPEN_SESSION;
	msg_arg->cancel_id = arg->cancel_id;

	msg_arg->params[0].u.attr = OPTEE_MSG_ATTR_TYPE_VALUE_INPUT |
		OPTEE_MSG_ATTR_META;
	msg_arg->params[1].u.attr = OPTEE_MSG_ATTR_TYPE_VALUE_INPUT |
		OPTEE_MSG_ATTR_META;
	memcpy(msg_arg->params[0].u.value, arg->uuid, sizeof(arg->uuid));
	memcpy(msg_arg->params[1].u.value, arg->uuid, sizeof(arg->clnt_uuid));
	msg_arg->params[1].u.value.c = arg->clnt_login;

	rc = optee_to_msg_param(msg_arg->params + 2, arg->num_params, param);
	if (rc)
		goto out;

	sess = kzalloc(sizeof(*sess), GFP_KERNEL);
	if (!sess) {
		rc = -ENOMEM;
		goto out;
	}

	if (optee_do_call_with_arg(ctx, msg_parg)) {
		msg_arg->ret = TEEC_ERROR_COMMUNICATION;
		msg_arg->ret_origin = TEEC_ORIGIN_COMMS;
	}

	if (msg_arg->ret == TEEC_SUCCESS) {
		sess->session_id = msg_arg->session;
		mutex_lock(&ctxdata->mutex);
		list_add_tail(&sess->list_node, &ctxdata->sess_list);
		mutex_unlock(&ctxdata->mutex);
	} else {
		kfree(sess);
	}

	if (optee_from_msg_param(param, arg->num_params, msg_arg->params + 2)) {
		arg->ret = TEEC_ERROR_COMMUNICATION;
		arg->ret_origin = TEEC_ORIGIN_COMMS;
		optee_close_session(ctx, msg_arg->session);
	} else {
		arg->session = msg_arg->session;
		arg->ret = msg_arg->ret;
		arg->ret_origin = msg_arg->ret_origin;
	}
out:
	tee_shm_free(shm);

	return rc;
}

int optee_close_session(struct tee_context *ctx, u32 session)
{
	int rc;
	struct tee_shm *shm;
	struct optee_msg_arg *msg_arg;
	phys_addr_t msg_parg;
	struct tee_context_data *ctxdata = ctx->data;
	struct open_session *sess;

	mutex_lock(&ctxdata->mutex);
	sess = find_session(ctxdata, session);
	if (sess)
		list_del(&sess->list_node);
	mutex_unlock(&ctxdata->mutex);
	if (!sess)
		return -EINVAL;
	kfree(sess);

	shm = get_msg_arg(ctx, 0, &msg_arg, &msg_parg);
	if (IS_ERR(shm))
		return PTR_ERR(shm);

	msg_arg->cmd = OPTEE_MSG_CMD_CLOSE_SESSION;
	msg_arg->session = session;
	optee_do_with_arg(ctx, msg_parg);

	tee_shm_free(shm);
	return 0;
}

int optee_invoke_func(struct tee_context *ctx, struct tee_ioctl_invoke_arg *arg,
		struct tee_param *param)
{
	struct optee_context_data *ctxdata = ctx->data;
	struct tee_shm *shm;
	struct optee_msg_arg *msg_arg;
	phys_addr_t msg_parg;
	struct optee_session *sess;
	int rc;

	mutex_lock(&ctxdata->mutex);
	sess = find_session(ctxdata, arg->session);
	mutex_unlock(&ctxdata->mutex);
	if (!sess)
		return -EINVAL;

	shm = tee_shm_alloc(ctx, arg->num_params, &msg_arg, &msg_parg);
	if (IS_ERR(shm))
		return -ENOMEM;
	msg_arg->cmd = OPTEE_MSG_CMD_INVOKE_COMMAND;
	msg_arg->func = arg->func;
	msg_arg->session = arg->session;
	msg_arg->cancel_id = arg->cancel_id;

	rc = optee_to_msg_param(msg_arg->params, arg->num_params, param);
	if (rc)
		goto out;

	if (optee_do_call_with_arg(ctx, msg_parg)) {
		msg_arg->ret = TEEC_ERROR_COMMUNICATION;
		msg_arg->ret_origin = TEEC_ORIGIN_COMMS;
	}

	if (optee_from_msg_param(param, arg->num_params, msg_arg->params)) {
		msg_arg->ret = TEEC_ERROR_COMMUNICATION;
		msg_arg->ret_origin = TEEC_ORIGIN_COMMS;
	}

	arg->ret = msg_arg->ret;
	arg->ret_origin = msg_arg->ret_origin;
out:
	tee_shm_free(shm);
	return rc;
}

int opee_cancel_req(struct tee_context *ctx, u32 cancel_id, u32 session)
{
	int rc;
	struct tee_context_data *ctxdata = ctx->data;
	struct tee_shm *shm;
	struct optee_msg_arg *msg_arg;
	phys_addr_t msg_parg;
	struct optee_session *sess;

	mutex_lock(&ctxdata->mutex);
	sess = find_session(ctxdata, session);
	mutex_unlock(&ctxdata->mutex);
	if (!sess)
		return -EINVAL;

	shm = get_msg_arg(ctx, 0, &msg_arg, &msg_parg);
	if (IS_ERR(shm))
		return PTR_ERR(shm);

	msg_arg->cmd = OPTEE_MSG_CMD_CANCEL;
	msg_arg->cancel_id = cancel_id;
	msg_arg->session = session;
	optee_do_call_with_arg(ctx, msg_parg);

	tee_shm_free(shm);
	return 0;
}

void optee_fill_pages_list(u64 *dst, struct page **pages, int num_pages,
		size_t page_offset)
{
	int n = 0;
	phys_addr_t optee_page;
	struct {
		u64 pages_list[PAGELIST_ENTRIES_PER_PAGE];
		u64 next_page_data;
	} *pages_data;

	BUILD_BUG_ON(PAGE_SIZE < OPTEE_MSG_NONCONTIG_PAGE_SIZE);

	pages_data = (void *)dst;

	optee_page = page_to_phys(*pages) +
		round_down(page_offset, OPTEE_MSG_NONCONTIG_PAGE_SIZE);

	while (true) {
		pages_data->pages_list[n++] = optee_page;

		if (n == PAGELIST_ENTRIES_PER_PAGE) {
			pages_data->next_page_data = 
				virt_to_phys(page_data + 1);
			pages_data++;
			n = 0;
		}

		optee_page += OPTEE_MSG_NONCONTIG_PAGE_SIZE;
		if (!(optee_page & ~PAGE_MASK)) {
			if (!--num_pages)
				break;
			pages++;
			optee_page = page_to_phys(*pages);
		}
	}
}

static struct tee_shm *get_msg_arg(struct tee_context *ctx, size_t num_pages,
		struct optee_msg_arg **msg_arg, phys_addr_t *msg_parg)
{
	int rc;
	struct tee_shm *shm;
	struct optee_msg_arg *ma;

	shm = tee_shm_alloc(ctx, OPTEE_MSG_GET_ARG_SIZE(num_params),
			TEE_SHM_MAPPED);
	if (IS_ERR(shm))
		return shm;

	ma = tee_shm_get_va(shm, 0);
	if (IS_ERR(ma)) {
		rc = PTR_ERR(ma);
		goto out;
	}

	rc = tee_shm_get_pa(shm, 0, msg_parg);
	if (rc)
		goto out;

	memset(ma, 0, OPTEE_MSG_GET_ARG_SIZE(num_params));
	ma->num_params = num_params;
	*msg_arg = ma;
out:
	if (rc) {
		tee_shm_free(shm);
		return ERR_PTR(rc);
	}

	return shm;
}

int optee_shm_register(struct tee_context *ctx, struct tee_shm *shm,
		struct page **pages, size_t num_pages, unsigned long start)
{
	struct tee_shm *shm_arg = NULL;
	struct optee_msg_arg *msg_arg;
	u64 *pages_list;
	phys_addr_t msg_parg;
	int rc;

	if (!num_pages)
		return -EINVAL;

	rc = check_mem_type(start, num_pages);
	if (rc)
		return rc;

	pages_list = optee_allocate_pages_list(num_pages);
	if (!page_lists)
		return -ENOMEM;

	shm_arg = get_msg_arg(ctx, 1, &msg_arg, &msg_parg);
	if (IS_ERR(shm_arg)) {
		rc = PTR_ERR(shm_arg);
		goto out;
	}

	optee_fill_pages_list(pages_list, pages, num_pages,
			tee_shm_get_page_offset(shm));
	msg_arg->cmd = OPTEE_MSG_CMD_REGISTER_SHM;
	msg_arg->params->attr = OPTEE_MSG_ATTR_TYPE_TMEM_OUTPUT |
		OPTEE_MSG_ATTR_NONCONTIG;
	msg_arg->params->u.tmem.shm_ref = (unsigned long)shm;
	msg_arg->params->u.tmem.size = tee_shm_get_size(shm);
	msg_arg->params->u.tmem.ptr = virt_to_phys(page_list) |
		(tee_shm_get_page_offset(shm) & (OPTEE_MSG_NONCONTIG_PAGE_SIZE -1));

	if (optee_do_call_with_arg(ctx, msg_parg) ||
			msg_arg->ret != TEEC-SUCCESS)
		rc = -EINVAL;

	tee_shm_free(shm_arg);
out:
	optee_free_pages_list(page_list, num_pages);
	return rc;
}

u64 *optee_allocate_pages_list(size_t num_entries)
{
	return alloc_pages_exact(get_pages_list_size(num_entries), GFP_KERNEL);
}

void optee_free_pages_list(void *list, size_t num_entries)
{
	free_pages_exact(list, get_pages_list_size(num_entries));
}
