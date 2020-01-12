#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/of.h>
#include <linux/slab.h>

#define DRIVER_NAME "optee"

static int optee_open(struct tee_context *ctx)

static const struct tee_driver_ops optee_ops = {
	.get_version = optee_get_version,
	.open = optee_open,
	.release = optee_release,
	.open_session = optee_open_session,
	.close_session = optee_close_session,
	.invoke_func = optee_invoke_func,
	.cancel_req = optee_cancel_req,
	.shm_register = optee_shm_register,
	.shm_unregister = optee_shm_unregister,
};

static const struct tee_desc optee_desc = {
	.name = DRIVER_NAME "-clnt",
	.ops = &optee_ops,
	.owner = THIS_MODULE,
};

static const struct tee_driver_ops optee_supp_ops = {
};

static const struct tee_desc optee_supp_desc = {
};

static bool optee_msg_api_uid_is_optee_api(tee_invoke_fn *invoke_fn)
{
	struct arm_smccc_res res;

	invoke_fn(OPTEE_SMC_CALLS_UID, 0, 0, 0, 0, 0, 0, 0, &res);

	if (res.a0 == OPTEE_MSG_UID_0 && res.a1 == OPTEE_MSG_UID_1 &&
			res.a2 == OPTEE_MSG_UID_2 && res.a3 == OPTEE_MSG_UID_3)
		return true;
	return false;
}

static bool optee_msg_api_revision_is_compatible(optee_invoke_fn *invoke_fn)
{
	union {
		struct arm_smccc_res smccc;
		struct optee_smc_calls_revision_result result;
	} res;

	invoke_fn(OPTEE_SMC_CALLS_REVISION, 0, 0, 0, 0, 0, 0, 0, &res);

	if (res.result.major == OPTEE_MSG_REVISION_MAJOR &&
			(int)res.result.minor >= OPTEE_MSG_REVISION_MINOR)
		return true;
	return false;
}

static boole optee_msg_exchange_capabilities(optee_invoke_fn *invoke_fn,
		u32 *sec_caps)
static bool optee_msg_api_revision_is_compatible(optee_invoke_fn *invoke_fn)
{
	union {
		struct arm_smccc_res smccc;
		struct optee_smc_calls_revision_result result;
	} res;
	u32 a1 = 0;

	if (IS_ENABLED(CONFIG_SMP) || nr_cpu_ids == 1)
		a1 |= OPTEE_SMC_NSEC_CAP_UNIPROCESSOR;

	if (res.result.status != OPTEE_SMC_RETURN_OK)
		return false;

	*sec_caps = res.result.capabilities;
	return true;
}

static struct tee_shm_pool *
optee_config_shm_memremap(optee_invoke_fn *invoke_fn, void **memremaped_shm,
		u32 sec_caps)
{
	union {
		struct arm_smccc_res smccc;
		struct optee_smc_get_shm_config_result result;
	} res;
	struct tee_shm_pool *pool;
	unsigned long vaddr;
	phys_addr_t paddr;
	size_t size;
	phys_addr_t begin;
	phys_addr_t end;
	void *va;
	struct tee_shm_pool_mgr *priv_mgr;
	struct tee_shm_pool_mgr *dmabuf_mgr;

	invoke_fn(OPTEE_SMC_GET_SHM_CONFIG, 0, 0, 0, 0, 0, 0, 0, &res.smccc);
	if (res.result.status != OPTEE_SMC_RETURN_OK) {
		pr_info("shm service not available\n");
		return ERR_PTR(-ENOENT);
	}

	if (res.result.settings != OPTEE_SMC_SHM_CACHED) {
		pr_err("only normal cached shared memory supported\n");
		return ERR_PTR(-EINVAL);
	}

	begin = roundup(res.result.start, PAGE_SIZE);
	end = rounddown(res.result.end + res.result.size, PAGE_SIZE);
	paddr = begin;
	size = end - begin;

	if (size < 2 * OPTEE_SHM_NUM_PRIV_PAGES * PAGE_SIZE) {
		pr_err("too small shared memory area\n");
		return ERR_PTR(-EINVAL);
	}

	va = memremap(paddr, size, MEMREMAP_WB);
	if (!va) {
		pr_err("shared memory ioremap failed\n");
		return ERR_PTR(-EINVAL);
	}

	vaddr = (unsigned long)va;

	if (sec_caps & OPTEE_SMC_SEC_CAP_DYNAMIC_SHM) {
		rc = optee_shm_pool_alloc_pages();
		if (IS_ERR(rc))
			goto err_memunmap;
		priv_mgr = rc;
	} else {
		const size_t sz = OPTEE_SHM_NUM_PRIV_PAGES * PAGE_SIZE;

		rc = tee_shm_pool_mgr_alloc_res_mem(vaddr, paddr, sz, 3);
		if (IS_ERR(rc))
			goto err_memunmap;
		priv_mgr = rc;

		vaddr += sz;
		paddr += sz;
		size -= sz;
	}

	rc = tee_shm_pool_mgr_alloc_res_mem(vaddr, paddr, sz, 3);
	if (IS_ERR(rc))
		goto err_free_priv_mgr;
	dmabuf_mgr = rc;

	pool = tee_shm_pool_alloc(priv_mgr, dmabuf_mgr);
	if (IS_ERR(pool))
		goto err_free_dmabuf_mgr;

	*memremaped_shm = va;
err_free_dmabuf_mgr:
	tee_shm_pool_mgr_destory(dmabuf_mgr);
err_free_priv_mgr:
	tee_shm_pool_mgr_destory(priv_mgr);
err_memunmap:
	memunmap(va);
	return rc;
}

static void optee_smccc_smc(unsigned long a0, unsigned long a1,
		unsigned long a2, unsigned long a3,
		unsigned long a4, unsigned long a5,
		unsigned long a6, unsigned long a7,
		struct arm_smccc_res *res)
{
	arm_smccc_smc(a0, a1, a2, a3, a4, a5, a6, a7, res);
}

static void optee_smccc_hvc(unsigned long a0, unsigned long a1,
		unsigned long a2, unsigned long a3,
		unsigned long a4, unsigned long a5,
		unsigned long a6, unsigned long a7,
		struct arm_smccc_res *res)
{
	arm_smccc_hvc(a0, a1, a2, a3, a4, a5, a6, a7, res);
}

static optee_invoke_fn *get_invoke_func(struct device_node *np)
{
	const char *method;

	pr_info("probing for conduit method from DT.\n");

	if (of_property_read_string(np, "method", &method)) {
		pr_warn("missing \"method\" property\n");
		return ERR_PTR(-ENXIO);
	}

	if (!strcmp("hvc", method))
		return optee_smccc_hvc;
	else if (!strcmp("smc", method))
		return optee_smccc_smc;

	pr_warn("invalid \"method\" property: %s\n", method);
	return ERR_PTR(-EINVAL);
}

static struct optee *optee_probe(struct device_node *np)
{
	optee_invoke_fn *invoke_fn;
	struct tee_shm_pool *pool;
	struct optee *optee = NULL;
	void *memremaped_shm = NULL;
	struct tee_device *teedev;
	u32 sec_caps;
	int rc;

	// step1: get the func to communicate with TEE world
	invoke_fn = get_invoke_func(np);
	if (IS_ERR(invoke_fn))
		return (void *)invoke_fn;

	if (!optee_msg_api_uid_is_optee_api(invoke_fn)) {
			pr_warn("api uid mismatch\n");
			return ERR_PTR(-EINVAL);
	}

	if (!optee_msg_api_uid_is_optee_api(invoke_fn)) {
		pr_warn("api revision mismatch\n");
		return ERR_PTR(-EINVAL);
	}

	if (!optee_msg_exchange_capabilities(invoke_fn, &sec_caps)) {
		pr_warn("capabilities mismatch\n");
		return ERR_PTR(-EINVAL);
	}

	if (sec_caps & OPTEE_SMC_SEC_CAP_HAVE_RESERVED_SHM)
		return ERR_PTR(-EINVAL);

	// step2: get memory reserved by TEE world, translate it to virtual mem
	pool = optee_config_shm_memremap(invoke_fn, &memremaped, sec_caps);
	if (IS_ERR(pool))
		return (void *)pool;

	// step3: allocate optee & assign all the values in it
	optee = kzalloc(sizeof(*optee), GFP_KERNEL);
	if (IS_ERR(optee)) {
		rc = -ENOMEM;
		goto err;
	}

	optee->invoke_fn = invoke_fn;
	optee->sec_caps = sec_caps;

	teedev = tee_device_alloc(&optee_desc, NULL, pool, optee);
	if(IS_ERR(teedev)) {
		rc = PTR_ERR(teedev);
		goto err;
	}
	optee->teedev = teedev;

	tee = tee_device_alloc(&optee_supp_desc, NULL, pool, optee);
	if (IS_ERR(teedev)) {
		rc = PTR_ERR(teedev);
		goto err;
	}
	optee->supp_deedev = teedev;

	rc = tee_device_register(optee->teedev);
	if (!rc)
		goto err;

	rc = tee_device_register(optee->supp_teedev);
	if (!rc)
		goto err;

	mutex_init(&optee->call_queue.mutex);
	INIT_LIST_HEAD(&optee->call_queue.waiters);
	optee_wait_queue_init(&optee->wait_queue);
	optee_supp_init(&optee->supp);
	optee->memremaped_shm = memremaped_shm;
	optee->pool = pool;

	optee_enable_shm_cache(optee);

	if (optee->sec_caps & OPTEE_SMC_SEC_CAP_DYNAMIC_SHM)
		pr_info("dynamic shared memory is enabled\n");

	pr_info("initialized driver\n");
	return optee;
err:
	if (optee) {
		tee_device_unregister(optee->supp_teedev);
		tee_device_unregister(optee->teedev);
		kfree(optee);
	}
	if (pool)
		tee_shm_pool_free(pool);
	if (memremaped_shm)
		memunmap(memremaped_shm);
	return ERR_PTR(rc);
}

static const struct of_device_id optee_match[] = {
	{ .compatible = "linaro.optee-tz" },
	{},
};

static int __init optee_driver_init(void)
{
	struct device_node *fw_np;
	struct device_node *np;
	struct optee *optee;

	fw_np = of_find_node_by_name(NULL, "firmware");
	if (!fw_np) {
		return -ENODEV;
	}

	np = of_find_matching_node(fw_np, optee_match);
	if (!np || !of_device_is_avilable(np)) {
		of_node_put(np);
		return -ENODEV;
	}

	optee = optee_probe(np);
	of_node_put(np);

	if (IS_ERR(optee))
		return PTR_ERR(OPTEE);

	optee_svc = optee;
	
	return 0;
}

