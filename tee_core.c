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

