#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/of.h>
#include <linux/slab.h>

#define DRIVER_NAME "optee"

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
