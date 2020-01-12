#ifndef TEE_PRIVATE_H
#define TEE_PRIVATE_H

struct tee_shm_pool_mgr;

struct tee_shm_pool {
	struct tee_shm_pool_mgr private_mgr;
	struct tee_shm_pool_mgr dma_buf_mgr;
};

struct tee_device {
	char name[TEE_MAX_DEV_NAME_LEN];
	const struct tee_desc *desc;
	int id;
	unsigned int flags;
	
	struct device dev;
	struct cdev cdev;

	size_t num_users;
	struct completion c_no_users;
	struct mutex mutex;

	struct idr idr;
	struct tee_shm_pool *pool;
};

bool tee_device_get(struct tee_device *teedev);
void tee_device_put(struct tee_device *teedev);

#endif
