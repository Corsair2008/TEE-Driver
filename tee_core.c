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

static init tee_release(struct inode *inode, file *filp)
{
	struct tee_context *ctx = filp->private;
	struct tee_device *teedev = ctx->teedev;
	struct tee_shm *shm;

	ctx->teedev->desc->ops->release(ctx);
	mutex_lock(&ctx->teedev->mutex);
	list_for_each_entry(shm, &ctx->list_shm, link)
		shm->ctx = NULL;
	mutex_unlock(&ctx->teedev->mutex);
	kfree(ctx);
	tee_device_put(teedev);
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

