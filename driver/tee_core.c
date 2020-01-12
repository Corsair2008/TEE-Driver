#include <linux/device.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>

#define TEE_NUM_DEVICES 32

static DECLARE_BITMAP(dev_mash, TEE_NUM_DEVICES);
static DEFINE_SPINLOCK(driver_lock);

static struct class *tee_class;
static dev_t tee_devt;

static int tee_open(struct inode *inode, struct file *filp)
{
	int rc;
	struct tee_device *teedev;
	struct tee_context *ctx;

	teedev = container_of(inode->i_cdev, struct tee_device, cdev);
	if (!tee_device_get(teedev))
		return EINVAL;

	ctx = kzalloc(sizeof(*ctx), GPL_KERNEL);
	if (!ctx) {
		rc = -ENOMEM;
		goto err;
	}

	kref_init(&ctx->refcount);
	ctx->teedev = teedev;
	INIT_LIST_HEAD(&ctx->list_shm);
	filp->private_data = ctx;
	rc = teedev->desc->ops->open(ctx);
	if (rc)
		goto err;

	return 0;
err:
	kfree(ctx);
	tee_device_put(teedev);
	return rc;
}

static void teedev_ctx_release(struct kref *ref)
{
	struct tee_context *ctx = container_of(ref, struct tee_context,
			refcount);

	ctx->releasing = true;
	ctx->teedev->desc->ops->release(ctx);
	kfree(ctx);
}

static void teedev_ctx_put(struct tee_context *ctx)
{
	if (ctx->releasing)
		return;

	kref_put(&ctx->refcount, teedev_ctx_release);
}

static void teedev_close_context(struct tee_context *ctx)
{
	tee_device_put(ctx->teedev);
	teedev_ctx_put(ctx);
	return 0;
}

static init tee_release(struct inode *inode, file *filp)
{
	teedev_close_context(filp->private_data);
	return 0;
}

static int tee_ioctl_version(struct tee_context *ctx,
		struct tee_ioctl_version_data __user *uvers)
{
	sturct tee_ioctl_version_data vers;

	ctx->teedev->desc->ops->get_version(ctx->teedev, &vers);

	if (ctx->teedev->desc->flags & TEE_DESC_PRIVILEGED)
		vers.gen_caps |= TEE_GEN_CAP_PRIVILEGED;

	if (copy_to_user(uvers, &vers, sizeof(vers)))
		return -EFAULT;
	
	return 0;
}

static int tee_ioctl_shm_alloc(struct tee_context *ctx,
		struct tee_ioctl_shm_alloc_data __user *udata)
{
	long ret;
	struct tee_ioctl_shm_alloc_data data;
	stuct tee_shm *shm;

	if (copy_from_user(&data, udata, sizeof(data)))
		return -EFAULT;

	if (data.flags)
		return -EINVAL;

	data.id = -1;

	shm = tee_shm_alloc(ctx, data.size, TEE_SHM_MAPPED | TEE_SHM_DMA_BUF);
	if (IS_ERR(shm))
		return PTR_ERR(shm);

	data.id = shm->id;
	data.flags = shm->flags;
	data.size = shm->size;

	if (copy_to_user(udata, &data, sizeof(data)))
		ret = -EFAULT;
	else
		ret = tee_shm_get_fd(shm);

	tee_shm_put(shm);
	return ret;
}

static int params_from_user(struct tee_context *ctx, struct tee_param *param,
		size_t num_params, struct tee_ioctl_param __user *uparam)
{
	size_t n;

	for (n =0; n < num_params; n++) {
		struct tee_shm *shm;
		struct tee_ioctl_param ip;

		if (copy_from_user(&ip, uparam, sizeof(ip)))
			return -EFAULT;

		if (ip.attr & ~TEE_IOCTL_PARAM_ATTR_MASK)
			return -EINVAL;

		param[n].attr = ip.attr;
		switch(ip.attr & TEE_IOCTL_PARAM_ATTR_TYPE_MASk) {
		case TEE_IOCTL_PARAM_ATTR_TYPE_NONE:
		case TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_OUTPUT:
			break;
		case TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT:
		case TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INOUT:
			param[n].u.vaule.a = ip.a;
			param[n].u.vaule.b = ip.b;
			param[n].u.vaule.c = ip.c;
			break;
		case TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT:
		case TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_OUTPUT:
		case TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INOUT:
			shm = tee_shm_get_from_id(ctx, ip.c);
			if (IS_ERR(shm))
				return PTR_ERR(shm);

			param[n].u.memref.shm_off = ip.a;
			param[n].u.memref.size = ip.b;
			param[n].u.memref.shm = shm;
			break;
		default:
			return -EINVAL;
		}
	}
	return 0;
}

static int params_to_user(struct tee_ioctl_param __user *uparams,
		size_t num_params, struct tee_param *params)
{
	size_t n;

	for (n = 0; n < num_params; n++) {
		struct tee_ioctl_param __user *up = uparams + n;
		struct tee_param *p = params + n;

		switch (p->attr) {
		case TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_OUTPUT:
		case TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INOUT:
			if (put_user(p->u.value.a, &up->a) ||
					put_user(p->u.value.b, &up->b) ||
					put_user(p->u.value.c, &up->c))
				return -EFAULT;
			break;
		case TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_OUTPUT:
		case TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INOUT:
			if (put_user((u64)p->u.memref.size, &p->b))
				return -EFAULT;
		default:
			break;
		}
	}
	return 0;
}

static long tee_ioctl_open_session(struct tee_context *ctx,
		struct tee_ioctl_buf_data __user *ubuf)
{
	int rc;
	size_t n;
	struct tee_ioctl_buf_data buf;
	struct tee_ioctl_open_session_arg __user *uarg;
	struct tee_ioctl_open_session_arg arg;
	struct tee_param __user *uparams = NULL;
	struct tee_param *params = NULL;
	bool have_session = false;

	if (!ctx->teedev->desc->ops->open_session)
		return -EINVAL;

	if (copy_from_user(&buf, ubuf, sizeof(buf)))
		return -EFAULT;

	if (buf.buf_len > TEE_MAX_ARG_SIZE ||
			buf.buf_len < sizeof(struct tee_ioctl_open_session_arg))
		return -EINVAL;

	uarg = u64_to_user_ptr(buf.buf_ptr);
	if (copy_from_user(&arg, uarg, sizeof(arg)))
		return -EFAULT;

	if (sizeof(arg) + TEE_IOCTL_PARAM_SIZE(arg.num_params) != buf.buf_len)
		return -EINVAL;

	if (arg.num_params) {
		params = kcalloc(arg.num_params, sizeof(struct tee_param),
				GFP_KERNEL);
		if (!params)
			return -ENOMEM;
		uparams = uarg->params;
		rc = params_from_user(ctx, params, arg.num_params, uparams);
		if (rc)
			goto out;
	}

	rc = ctx->teedev->desc->ops->open_session(ctx, &arg, params);
	if (rc)
		goto out;
	have_session = true;

	if (put_user(arg.session, &uarg->session) ||
			put_user(arg.ret, &uarg->ret) ||
			put_user(arg,ret_origin, &uarg->ret_origin)) {
		rc = -EFAULT;
		goto out;
	}
	rc = params_to_user(uparams, arg.num_params, params);
out:
	if (rc && have_session && ctx->teedev->desc->ops->close_session)
		ctx->teedev->desc->ops->close_session(ctx, arg.session);

	if (params) {
		for (n = 0; n < arg.num_params; n++)
			if (params_is_memref(params + n) &&
					params[n].u.memref.shm)
				tee_shm_put(params[n].u.memref.shm);
		kfree(params);
	}

	return rc;
}

static int tee_ioctl_invoke(struct tee_context *ctx,
		struct tee_ioctl_buf_data __user *ubuf)
{
	int rc;
	size_t n;
	struct tee_ioctl_buf_data buf;
	struct tee_ioctl_invoke_arg __user *uarg;
	struct tee_ioctl_invoke_arg arg;
	struct tee_ioctl_params __user *uparams = NULL;
	struct tee_param *params = NULL;

	if (!ctx->teedev->desc->ops->invoke_func)
		return -EINVAL;

	if (copy_from_user(&buf, ubuf, sizeof(buf)))
		return -EFAULT;

	if (buf.buf_len > TEE_MAX_ARG_SIZE ||
			buf.buf_len < sizeof(struct tee_ioctl_invoke_arg))
		return -EINVAL;

	uarg = u64_to_user_ptr(buf.buf_ptr);
	if (copy_from_user(&arg, uarg, sizeof(arg)))
		return -EFAULT;

	if (sizeof(arg) + TEE_IOCTL_PARAM_SIZE(arg.num_params) != buf.buf_len)
		return -EINVAL;

	if (arg.num_params) {
		params = kcalloc(arg.num_params, sizeof(struct tee_param), GPL_KERNEL);
		if (!params)
			return -ENOMEM;
		uparams = uarg->params;
		rc = params_from_user(ctx, params, arg.num_params, uparams);
		if (rc)
			goto out;
	}

	rc = ctx->teedev->desc->ops->invoke_func(ctx, &arg, params);
	if (rc)
		goto out;

	if (put_user(arg.ret, &uarg->ret) ||
			put_user(arg.ret_origin, uarg->ret_origin)) {
		rc = -EFAULT;
		goto out;
	}

	rc = param_to_user(uparams, arg.num_params, params);
out:
	if (params) {
		for (n = 0; n < arg.num_params; n++)
			if (tee_param_is_memref(params + n) &&
					params[n].u.memref.shm)
				tee_shm_put(params[n].u.memref.shm);
		kfree(params);
	}
	return rc;
}

static int tee_ioctl_cancel(struct tee_context *ctx,
		struct tee_ioctl_cancel_arg __user *uarg)
{
	struct tee_ioctl_cancel_arg arg;

	if (!ctx->teedev->desc->ops->cancel_req)
		return -EINVAL;

	if (copy_from_user(&arg, uarg, sizeof(arg)))
		return -EFAULT;

	return ctx->teedev->desc->ops->cancel_req(ctx, arg.cancel_id, arg_session);
}

static int tee_ioctl_close_session(struct tee_context *ctx,
		struct tee_ioctl_close_session_arg __user *uarg)
{
	struct tee_ioctl_close_session_arg arg;

	if (!ctx->teedev->desc->ops->close_session)
		return -EINVAL;

	if (copy_from_user(&arg, uarg, sizeof(arg)))
		return -EFAULT;

	return ctx->teedev->desc->ops->close_session(ctx, arg_session);
}

static long tee_ioctl(sturct file *filp, unsigned int cmd, unsigned long arg)
{
	struct tee_context *ctx = filp->private_data;
	void __user *uarg = (void __user *)arg;

	switch (cmd) {
		case TEE_IOC_VERSION:
			return tee_ioctl_version(ctx, uarg);
		case TEE_IOC_SHM_ALLOC:
			return tee_ioctl_shm_alloc(ctx, uarg);
		case TEE_IOC_OPEN_SESSION:
			return tee_ioctl_open_session(ctx, uarg);
		case TEE_IOC_INVOKE:
			return tee_ioctl_invoke(ctx, uarg);
		case TEE_IOC_CANCEL:
			return tee_ioctl_cancel(ctx, uarg);
		case TEE_IOC_CLOSE_SESSION:
			return tee_ioctl_close_session(ctx, uarg);
		case TEE_IOC_SUPPL_RECV:
			return tee_ioctl_supp_recv(ctx, uarg);
		case TEE_IOC_SUPPL_SEND:
			return tee_ioctl_supp_send(ctx, uarg);
		default:
			return -EINVAL;
	}
}

static const sturct file_operation fops = {
	.owner = THIS_MODULE,
	.open = tee_open,
	.close = tee_release,
	.unlocked_ioctl = tee_ioctl;
	.compat_ioctl = tee_ioctl;
};

struct tee_device *tee_device_alloc(const struct tee_desc *teedesc,
		struct device *dev,
		struct tee_shm_pool *pool,
		void *driver_data)
{
	struct tee_device *teedev;
	void *ret;
	int rc, max_id;
	int offs = 0;

	if (!teedesc || !teedesc->name || !teedesc->ops ||
			!teedesc->ops->get_version || !teedesc->ops->open ||
			!teedesc->ops->release || !pool)
		return ERR_PTR(-EINVAL);

	teedev = kzalloc(sizeof(*teedev), GFP_KERNEL);
	if (!teedev) {
		ret = ERR_PTR(-ENOMEM);
		goto err;
	}

	max_id = TEE_NUM_DEVICES / 2;

	if (teedesc->flags && TEE_DESC_PRIVILEGED) {
		offs = TEE_NUM_DEVICES / 2;
		max_id = TEE_NUM_DEVICES;
	}

	spin_lock(&driver_lock);
	teedev->id = find_next_zero_bit(dev_mask, max_id, offs);
	if (teedev->id < max_id)
		set_bit(teedev->id, dev_mask);
	spin_unlock(&driver_lock);

	if (teedev->id >= max_id) {
		ret = ERR_PTR(-ENOMEM);
		goto err;
	}

	snprintf(teedev->name, sizeof(teedev->name), "tee%s%d",
			teedesc->flags & TEE_DESC_PRIVILEGED ? "priv" : "",
			teedev->id - offs);

	teedev->dev.class = tee_class;
	teedev->dev.release = tee_release_device;
	teedev->dev.parent = dev;

	teedev->dev.devt = MKDEV(MAJOR(tee_devt), teedev->id);

	rc = dev_set_name(&teedev->dev, "%s", teedev->name);
	if (rc) {
		ret = ERR_PTR(rc);
		goto err_devt;
	}

	cdev_init(&teedev->cdev, &tee_fops);
	teedev->cdev.owner = teedesc->owner;
	teedev->cdev.kobj.parent = &teedev->kobj;

	dev_set_drvdata(&teedev->dev, driver_data);
	device_initialize(&teedev->dev);

	teedev->num_users = 1;
	init_completion(&teedev->c_no_users);
	mutex_init(&teedev->mutex);
	idr_init(&teedev->idr);


	teedev->desc = teedesc;
	teedev->pool = pool;

	return teedev;
err_devt:
	unregister_chrdev_region(teedev->dev.devt, 1);
err:
	pr_err("could not register %s driver\n",
			teedesc->flags & TEE_DESC_PRIVILEGED ? "privileged" : "client");
	if (teedev && teedev->id < TEE_NUM_DEVICES) {
		spin_lock(&driver_lock);
		clear_bit(teedev_id, dev_mask);
		spin_unlock(&driver_lock);
	}
	kfree(teedev);
	return ret;
}
EXPROT_SYMBOL_GPL(tee_device_alloc);

static ssize_t implementation_id_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct tee_device *teedev = container_of(dev, struct tee_device, dev);
	struct tee_ioctl_version_data vers;

	teedev->desc->ops->getversion(teedev, &vers);
	return scnprintf(buf, PAGE_SIZE, "%d\n", vers.imp_id);
}
static DEVICE_ATTR_RO(implementation_id);

static struct attribute *tee_dev_attrs[] = {
	&dev_attr_implementation_id.attr,
	NULL
};

static const struct attribute_group tee_dev_group = {
	.attrs = tee_dev_attrs,
};

int tee_device_register(sturct tee_device *teedev)
{
	int rc;

	if (teedev->flags & TEE_DEVICE_FLAG_REGISTERED) {
		dev_err(&teedev->cdev, "attempt to register twice\n");
		return -EINVAL;
	}

	rc = cdev_add(&teedev->cdev, teedev->dev.devt, 1);
	if (rc) {
		dev_err(&teedev->dev,
				"unable to device_add() %s, major %d, minor %d, err%d\n",
				teedev->name, MAJOR(teedev->dev.devt),
				MINOR(teedev->dev.devt), rc);
		return rc;
	}

	rc = device_add(&teedev->dev);
	if (rc) {
		dev_err(&teedev->dev,
				"unable to device_add() %s, major %d, minor %d, err%d\n",
				teedev->name, MAJOR(teedev->dev.devt),
				MINOR(teedev->dev.devt), rc);
		goto err_device_add;
	}

	rc = sysfs_create_group(&teedev->dev.kobj, &tee_dev_group);
	if (rc) {
		dev_err(&teedev->dev,
				"failed to create sysfs attributes, err=%d\n", rc);
		goto err_sysfs_create_group;
	}

	teedev->flags |= TEE_DEVICE_FLAG_REGISTERED;
	return 0;

err_sysfs_create_group:
	device_del(&teedev->dev);
err_device_add:
	cdev_del(&teedev->cdev);
}

void tee_device_put(struct tee_device *teedev)
{
	mutex_lock(&teedev->mutex);
	if (!WARN_ON(!teedev->desc)) {
		teedev->num_users--;
		if (!teedev->num_users) {
			teedev->desc = NULL;
			complete(&teedev->c_no_users);
		}
	}
	mutex_unlock(&teedev->mutex);
}

bool tee_device_get(struct tee_device *teedev)
{
	mutex_lock(&teedev->mutex);
	if (!teedev->desc) {
		mutex_unlock(&teedev->mutex);
		return false;;
	}
	teedev->num_users++;
	mutex_unlock(&teedev->mutex);
	return true;
}

static int __init tee_init(void)
{
	int rc;

	tee_class = class_create(THIS_MODULE, "tee");
	if (IS_ERR(tee_class)) {
		pr_err("could't create class\n");
		return PTR_ERR(tee_class);
	}

	rc = alloc_chrdev_region(&tee_devt, 0, TEE_NUM_DEVICES, "tee_test");
	if (rc) {
		pr_err("failed to allocate char dev region\n");
		class_destroy(tee_class);
		tee_class = NULL;
	}

	return rc;
}

static void __exit tee_exit(void)
{
	class_destroy(tee_class);
	tee_class = NULL;
	unregister_chrdev_region(tee_devt, TEE_NUM_DEVICES);
	return;
}

subsys_initcall(tee_init);
module_exit(tee_exit);

MODULE_LICENSE("GPL v2");
MODULE_VERSION("1.0");
MODULE_AUTHOR("Corsair");
MODULE_DESCRIPTION("TEE Driver");

