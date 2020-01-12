struct optee_call_queue {
	struct list_head waiters;
	struct mutex mutex;
};

struct optee_wait_queue {
	struct list_head db;
	struct mutex mu;
};
