struct device;
struct tee_device;

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
