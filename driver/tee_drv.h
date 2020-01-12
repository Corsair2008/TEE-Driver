struct device;
struct tee_device;

struct tee_shm {
	struct tee_device *teedev;
	struct tee_context *ctx;
	struct list_head link;
	phys_addr_t paddr;
	void *kaddr;
	size_t size;
	unsigned int offset;
	struct page **pages;
	size_t num_pages;
	struct dma_buf *dma_buf;
	u32 flags;
	int id;
};

struct tee_driver_ops {
	void (*get_version)(struct tee_device *teedev,
			struct tee_ioctl_version_data *vers);
	int (*open)(struct tee_context *ctx);
	void (*release)(struct tee_context *ctx);
	int (*open_session)(struct tee_context *ctx,
			struct tee_ioctl_open_session_arg *arg,
			struct tee_param *param);
	void (*close_session)(struct tee_context *ctx, u32 session);
	int (*invoke_session)(struct tee_context *ctx,
			struct tee_ioctl_invoke_arg *arg,
			struct tee_param *param);
	int (*cancle_req)(struct tee_context *ctx, u32 cancel_id, u32 session);
	int (*supp_recv)(struct tee_context *ctx, u32 *func, u32 *num_params,
			struct tee_param *param);
	int (*supp_send)(struct tee_context *ctx, u32 ret, u32 num_params,
			struct tee_param *param);
};

struct tee_desc {
	const char *name;
	const struct tee_driver_ops *ops;
	struct module *owner;
	u32 flags;
};

static inline void tee_shm_pool_mgr_destory(struct tee_shm_pool_mgr *poolm)
{
	poolm->ops->destory_poolmgr(poolm);
}

static inline bool tee_shm_is_registered(struct tee_shm *shm)
{
	return shm && (shm->flags & TEE_SHM_REGISTER);
}
