#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/namei.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/pagemap.h>
#include "jobhdr.h"
#include "sj_job.h"

#define MAX_JOB 512
asmlinkage extern long (*sysptr)(void *arg, int argslen);

struct task_struct *sj_worker;
int curr_job;
int err_code[512] = {0};
DECLARE_BITMAP(jobs, 512);
DECLARE_BITMAP(jid, 512);

struct sj_workqueue_struct {
	struct list_head work_queue;
	/* Lock for work queue */
	struct mutex queue_lock;
	int max;
	int curr;
};

struct sj_work_struct {
	struct list_head entry;
	int id;
	int type;
	int priority;
	void *args;
	int command;
};

struct sj_workqueue_struct *sj;

static int get_jobid(void)
{
	int i = 0;

	for (i = 1; i < MAX_JOB; i++) {
		if (!test_bit(i, jid)) {
			bitmap_set(jid, i, 1);
			break;
		}
	}
	return i;
}

static int sj_change_priority(struct job_arg *user_arg)
{
	int ret = 0;
	int found = 0;
	int jobid = 0;
	int priority = 0;
	struct sj_work_struct *new;
	struct sj_work_struct *prev;
	struct sj_work_struct *new_tmp;
	struct sj_job_priority *args = user_arg->arg;

	get_user(jobid, &args->id);
	get_user(priority, &args->priority);

	mutex_lock(&sj->queue_lock);

	list_for_each_entry_safe(new, prev, &sj->work_queue, entry) {
		if (new->id == jobid) {
			found = 1;
			list_del(&new->entry);
		break;
		}
	}
	if (!found) {
		ret = -EINVAL;
		goto out;
	}

	if (new->priority == priority)
		goto out;
	new->priority = priority;

	list_for_each_entry_safe(new_tmp, prev, &sj->work_queue, entry) {
		if (new->priority < new_tmp->priority)
			break;
	}

	new_tmp = list_prev_entry(new_tmp, entry);
	list_add(&new->entry, &new_tmp->entry);

out:
	mutex_unlock(&sj->queue_lock);

	return ret;
}

static int sj_concat_files(char *file1, char *file2)
{
	int ret = -EOPNOTSUPP;

	return ret;
}

static int sj_process_encrypt(struct sj_work_struct *sj_work)
{
	int ret = 0;
	char *outfile = NULL;
	char *ext = ".enc";
	struct sj_job_encrypt *args = (struct sj_job_encrypt *)sj_work->args;

	outfile = kzalloc(strlen(args->file) + strlen(ext) + 1, GFP_KERNEL);
	if (!outfile || IS_ERR(outfile)) {
		ret =  PTR_ERR(outfile);
		goto out;
	}
	memcpy(outfile, args->file, strlen(args->file));
	memcpy(outfile + strlen(args->file), ext, strlen(ext) + 1);
	ret = sj_xcrypt_file(args->file, outfile, args->key,
			     strlen(args->key), 1);
	kfree(outfile);
out:
	kfree(args->file);
	kfree(args->key);
	return ret;
}

static int sj_process_decrypt(struct sj_work_struct *sj_work)
{
	int ret = 0;
	int out_len = 0;
	char *outfile = NULL;
	char *ext = ".enc";
	char *ext_p = NULL;
	struct sj_job_encrypt *args = (struct sj_job_encrypt *)sj_work->args;

	ext_p = strstr(args->file, ext);

	if (!ext_p)
		out_len = strlen(args->file) + 1;
	else
		out_len = ext_p - args->file + 1;

	outfile = kzalloc(out_len, GFP_KERNEL);
	if (!outfile || IS_ERR(outfile)) {
		ret =  PTR_ERR(outfile);
		goto out;
	}

	memcpy(outfile, args->file, out_len - 1);
	ret = sj_xcrypt_file(args->file, outfile, args->key,
			     strlen(args->key), 0);
	kfree(outfile);
out:
	kfree(args->file);
	kfree(args->key);
	return ret;
}

static int sj_process_decompress(struct sj_work_struct *sj_work)
{
	int ret = 0;
	int out_len = 0;
	char *outfile = NULL;
	char *ext = ".cmp";
	char *ext_p = NULL;
	char *infile = sj_work->args;

	ext_p = strstr(infile, ext);
	if (!ext_p) {
		ret = -EINVAL;
		goto out;
	} else {
		out_len = ext_p - infile + 1;
	}

	outfile = kzalloc(out_len, GFP_KERNEL);
	if (!outfile || IS_ERR(outfile)) {
		ret =  PTR_ERR(outfile);
		goto out;
	}

	memcpy(outfile, infile, out_len - 1);
	ret = sj_compress_file(infile, outfile, 0);
	kfree(outfile);
out:
	return ret;
}

static int sj_process_compress(struct sj_work_struct *sj_work)
{
	int ret = 0;
	char *outfile = NULL;
	char *ext = ".cmp";
	char *infile = sj_work->args;

	outfile = kzalloc(strlen(infile) + strlen(ext) + 1, GFP_KERNEL);
	if (!outfile || IS_ERR(outfile)) {
		ret =  PTR_ERR(outfile);
		goto out;
	}
	memcpy(outfile, infile, strlen(infile));
	memcpy(outfile + strlen(infile), ext, strlen(ext) + 1);
	ret = sj_compress_file(infile, outfile, 1);
	kfree(outfile);
out:
	return ret;
}

static int sj_process_job(struct sj_work_struct *sj_work)
{
	int ret = 0;

	if (sj_work->command == STRCONCAT) {
		struct strconcat *args = (struct strconcat *)sj_work->args;

		if (!args->str1)
			goto out;
		if (!args->str2)
			goto out;
		msleep(5000);
		ret = sj_concat_files(args->str1, args->str2);
		kfree(args->str1);
		kfree(args->str2);
	} else if (sj_work->command == ENCRYPT) {
		ret = sj_process_encrypt(sj_work);
	} else if (sj_work->command == DECRYPT) {
		ret = sj_process_decrypt(sj_work);
	} else if (sj_work->command == COMPRESS) {
		ret = sj_process_compress(sj_work);
	} else if (sj_work->command == DECOMPRESS) {
		ret = sj_process_decompress(sj_work);
	}
out:
	err_code[sj_work->id] = ret;
	bitmap_set(jobs, sj_work->id, 1);
	kfree(sj_work->args);
	return ret;
}

/* This is producer */
static int sj_queue_work(struct job_arg *job)
{
	int ret = 0;
	struct sj_work_struct *sj_work;

	mutex_lock(&sj->queue_lock);
	if (sj->curr >= sj->max)
		ret = -EBUSY;

	/* Free sj_work in consumer */
	sj_work = kmalloc(sizeof(*sj_work), GFP_KERNEL);
	if (!sj_work) {
		ret = -ENOMEM;
		goto out;
	}
	sj->curr++;
	sj_work->id = get_jobid();
	sj_work->type = 1;
	sj_work->priority = job->priority;
	sj_work->command = job->op;
	sj_work->args = job->arg;
	ret = sj_work->id;

	list_add_tail(&sj_work->entry, &sj->work_queue);
	bitmap_clear(jobs, sj_work->id, 1);
	if (sj->curr == 1)
		wake_up_process(sj_worker);
out:
	mutex_unlock(&sj->queue_lock);

	return ret;
}

/* This is consumer thread */
static int sj_worker_thread(void *data)
{
	struct sj_work_struct *new = NULL;

	pr_info("Consumer thread started\n");

	while (1) {
		/* check if i need to stop */
		if (kthread_should_stop()) {
			pr_info("Consumer thread should stop\n");
			return 0;
		}

		/* sleep if queue is empty */
		set_current_state(TASK_INTERRUPTIBLE);
		mutex_lock(&sj->queue_lock);
		if (sj->curr == 0) {
			mutex_unlock(&sj->queue_lock);
			schedule();
			continue;
		} else {
			set_current_state(TASK_RUNNING);
		}

		/* fetch a job from queue */
		new = list_first_entry(&sj->work_queue, struct sj_work_struct,
				       entry);
		list_del(&new->entry);
		sj->curr--;
		mutex_unlock(&sj->queue_lock);

		/* work on the job */
		curr_job = new->id;
		sj_process_job(new);
		curr_job = 0;
		bitmap_clear(jid, new->id, 1);
		kfree(new);
	}
}

static int init_submit_job_worker(void)
{
	int ret = 0;

	sj_worker = kthread_create(sj_worker_thread, NULL, "sj_worker");
	if (IS_ERR(sj_worker)) {
		ret = PTR_ERR(sj_worker);
		sj_worker = NULL;
		goto out;
	}
	set_task_state(sj_worker, TASK_INTERRUPTIBLE);
out:
	return ret;
}

static int exit_submit_job_worker(void)
{
	pr_info("Thread Destroyed\n");
	kthread_stop(sj_worker);
	return 0;
}

asmlinkage long submitjob(void *arg, int argslen)
{
	int ret = 0;
	struct job_arg *job = NULL;
	struct job_arg *user_arg = (struct job_arg *)arg;
	struct strconcat *user_cmd = NULL;
	void *cmd_args = NULL;
	int cmd_args_len;
	char *str1, *str2;
	int found = 0, rc;

	struct sj_work_struct *new;
	int len1, len2;
	struct sj_job_list *l, *head;

	struct sj_work_struct *prev;
	int jobid;

	struct sj_job_status *st;

	char *arg1 = NULL;
	char *arg2 = NULL;
	struct filename *in_filename = NULL;
	struct file *in_filp = NULL;
	char *file_name = NULL;
	char *abs_path = NULL;

	if (!arg) {
		return -EINVAL;
		goto out;
	}

	job = kzalloc(sizeof(*job), GFP_KERNEL);
	if (!job) {
		ret = -ENOMEM;
		goto out;
	}

	if (copy_from_user(job, user_arg, sizeof(*job))) {
		ret = -EFAULT;
		goto out;
	}

	/* get the job type */
	switch (job->op) {
	case STRCONCAT:
		user_cmd = (struct strconcat *)user_arg->arg;
		cmd_args = kmalloc(sizeof(*cmd_args),
				   GFP_KERNEL);
		if (!cmd_args) {
			ret = -ENOMEM;
			goto out;
		}
		cmd_args_len = sizeof(struct strconcat);
		rc = copy_from_user((struct strconcat *)cmd_args, user_cmd,
				    cmd_args_len);
		if (rc < 0) {
			ret = -EFAULT;
			goto out;
		}
		job->arg = cmd_args;

		str1 = kmalloc(strlen(user_cmd->str1) + 1, GFP_KERNEL);
		str2 = kmalloc(strlen(user_cmd->str2) + 1, GFP_KERNEL);
		memset(str1, 0, strlen(user_cmd->str1) + 1);
		memset(str2, 0, strlen(user_cmd->str2) + 1);

		rc = copy_from_user(str1, user_cmd->str1,
				    strlen(user_cmd->str1));
		if (rc < 0) {
				ret = -EFAULT;
				goto out;
		}
		rc = copy_from_user(str2, user_cmd->str2,
				    strlen(user_cmd->str2));
		if (rc < 0) {
			ret = -EFAULT;
			goto out;
		}

		((struct strconcat *)cmd_args)->str1 = str1;
		((struct strconcat *)cmd_args)->str2 = str2;

		break;
	case ENCRYPT:/* Fall through */
	case DECRYPT:
		cmd_args = kzalloc(sizeof(*cmd_args),
				   GFP_KERNEL);
		if (!cmd_args) {
			ret = -ENOMEM;
			goto err_out;
		}
		cmd_args_len = sizeof(struct sj_job_encrypt);
		if (copy_from_user((struct sj_job_encrypt *)cmd_args,
				   user_arg->arg, cmd_args_len)) {
			ret = -EFAULT;
			goto err_out;
		}
		str1 = ((struct sj_job_encrypt *)user_arg->arg)->file;
		in_filename = getname(str1);
		in_filp = filp_open(in_filename->name, O_RDONLY, 0);
		if (!in_filp || IS_ERR(in_filp)) {
			ret = PTR_ERR(in_filp);
			putname(in_filename);
			goto err_out;
		}
		file_name = kzalloc(PAGE_CACHE_SIZE, GFP_KERNEL);
		if (!file_name || IS_ERR(file_name)) {
			ret = -ENOMEM;
			filp_close(in_filp, NULL);
			putname(in_filename);
			goto err_out;
		}
		abs_path = dentry_path_raw(in_filp->f_path.dentry, file_name,
					   PAGE_CACHE_SIZE);
		filp_close(in_filp, NULL);
		putname(in_filename);
		arg1 = kzalloc(strlen(abs_path) + 1, GFP_KERNEL);
		if (!arg1 || IS_ERR(arg1)) {
			ret = -ENOMEM;
			goto err_out;
		}
		memcpy(arg1, abs_path, strlen(abs_path) + 1);
		kfree(file_name);
		str2 = ((struct sj_job_encrypt *)user_arg->arg)->key;
		if (!str1 || !str2) {
			ret = -EINVAL;
			goto err_out;
		}
		arg2 = kzalloc(strlen_user(str2) + 1, GFP_KERNEL);
		if (!arg2 || IS_ERR(arg2)) {
			ret = -ENOMEM;
			goto err_out;
		}
		if (copy_from_user(arg2, str2, strlen_user(str2))) {
			ret = -EFAULT;
			goto err_out;
		}
		((struct sj_job_encrypt *)cmd_args)->file = arg1;
		((struct sj_job_encrypt *)cmd_args)->key = arg2;
		job->arg = cmd_args;
		break;
	case COMPRESS: /*fall through*/
	case DECOMPRESS:
		if (!user_arg->arg) {
			ret = -EINVAL;
			goto out;
		}
		in_filename = getname(user_arg->arg);
		in_filp = filp_open(in_filename->name, O_RDONLY, 0);
		if (!in_filp || IS_ERR(in_filp)) {
			ret = PTR_ERR(in_filp);
			putname(in_filename);
			goto err_out;
		}
		file_name = kzalloc(PAGE_CACHE_SIZE, GFP_KERNEL);
		if (!file_name || IS_ERR(file_name)) {
			ret = -ENOMEM;
			filp_close(in_filp, NULL);
			putname(in_filename);
			goto err_out;
		}
		abs_path = dentry_path_raw(in_filp->f_path.dentry, file_name,
					   PAGE_CACHE_SIZE);
		filp_close(in_filp, NULL);
		putname(in_filename);
		arg1 = kzalloc(strlen(abs_path) + 1, GFP_KERNEL);
		if (!arg1 || IS_ERR(arg1)) {
			ret = PTR_ERR(arg1);
			goto err_out;
		}
		memcpy(arg1, abs_path, strlen(abs_path) + 1);
		kfree(file_name);
		job->arg = arg1;
		break;
	case LIST:

		len1 = sizeof(struct sj_job_list);
		l = kzalloc(len1, GFP_KERNEL);
		len2 = sizeof(struct sj_job);
		l->list = kzalloc(len2 * 512, GFP_KERNEL);
		if (!l || !l->list) {
			ret = -ENOMEM;
			goto out;
		}

		head = (struct sj_job_list *)l->list;
		mutex_lock(&sj->queue_lock);
		list_for_each_entry(new, &sj->work_queue, entry) {
			l->list->id = new->id;
			l->list->op = new->command;
			l->list = l->list + 1;
		}
		l->count = sj->curr;
		ret = l->count;
		mutex_unlock(&sj->queue_lock);

		rc = copy_to_user(((struct sj_job_list *)user_arg->arg)->list,
				  head, len2 * 512);
		if (rc < 0) {
			ret = -EFAULT;
			kfree(head);
			kfree(l);
			goto out;
		}
		if (put_user(l->count, &((struct sj_job_list *)
					 user_arg->arg)->count) < 0) {
			ret = -EFAULT;
			kfree(head);
			kfree(l);
			goto out;
		}
		kfree(head);
		kfree(l);
		goto out;
	case STATUS:
		st = (struct sj_job_status *)user_arg->arg;
		get_user(jobid, &st->id);

		mutex_lock(&sj->queue_lock);
		if (curr_job == jobid) {
			put_user(INPROGRESS, &st->status);
			put_user(0, &st->err);
			mutex_unlock(&sj->queue_lock);
			goto out;
		} else {
			list_for_each_entry(new, &sj->work_queue, entry) {
				if (new->id == jobid) {
					put_user(INQUEUE, &st->status);
					put_user(0, &st->err);
					mutex_unlock(&sj->queue_lock);
					goto out;
				}
			}
		}
		mutex_unlock(&sj->queue_lock);

		if (test_bit(jobid, jobs)) {
			put_user(COMPLETED, &st->status);
			put_user(err_code[jobid], &st->err);
		} else {
			ret = -EINVAL;
		}
		goto out;
	case REMOVE:
		found = 0;
		get_user(jobid, (int *)user_arg->arg);
		mutex_lock(&sj->queue_lock);
		list_for_each_entry_safe(new, prev, &sj->work_queue, entry) {
			if (new->id != jobid)
				continue;
			found = 1;
			switch (new->command) {
			case STRCONCAT:
				kfree(((struct strconcat *)new->args)->str1);
				kfree(((struct strconcat *)new->args)->str2);
				break;
			case ENCRYPT:
				kfree(((struct sj_job_encrypt *)new->args)->key);
				kfree(((struct sj_job_encrypt *)new->args)->file);
				break;
			case DECRYPT:
				kfree(((struct sj_job_encrypt *)new->args)->key);
				kfree(((struct sj_job_encrypt *)new->args)->file);
				break;
			default:
				break;
			}
			kfree(new->args);
			list_del(&new->entry);
			kfree(new);
			sj->curr--;
			break;
		}
		mutex_unlock(&sj->queue_lock);
		if (found == 1)
			ret = 0;
		else
			ret = -1;
		goto out;
	case CHPRIORITY:
		ret = sj_change_priority(user_arg);
		goto out;
	default:
		break;
	}

	ret = sj_queue_work(job);
/*err_buf:
 kfree(command);*/
out:
	return ret;
err_out:
	kfree(arg1);
	kfree(arg2);
	kfree(cmd_args);
	kfree(job);
	return ret;
}

static int __init init_sys_submitjob(void)
{
	int ret = 0;

	pr_info("installed new sys_submitjob module\n");
	if (!sysptr)
		sysptr = submitjob;

	sj = kzalloc(sizeof(*sj), GFP_KERNEL);
	if (!sj) {
		ret = -ENOMEM;
		goto out;
	}

	mutex_init(&sj->queue_lock);
	INIT_LIST_HEAD(&sj->work_queue);
	sj->max = MAX_JOB;
	sj->curr = 0;

	ret = init_submit_job_worker();
	curr_job = 0;
	if (ret)
		kfree(sj);

	bitmap_zero(jid, 512);

	/* declare bitmap here */
	bitmap_zero(jobs, 512);

/* wake_up_process(sj_worker); */
out:
	return 0;
}

static void  __exit exit_sys_submitjob(void)
{
	if (sysptr)
		sysptr = NULL;

	exit_submit_job_worker();

	pr_info("removed sys_submitjob module\n");
}
module_init(init_sys_submitjob);
module_exit(exit_sys_submitjob);
MODULE_LICENSE("GPL");
