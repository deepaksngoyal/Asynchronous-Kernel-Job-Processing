#include <asm/unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <ctype.h>
#include <openssl/md5.h>
#include "jobhdr.h"

#ifndef __NR_submitjob
#error submitjob system call not defined
#endif

static int parse_args_for_list(int argc, char *args[], struct job_arg *ja);
static int parse_args_for_remove(int argc, char *args[], struct job_arg *ja);
static int parse_args_for_status(int argc, char *args[], struct job_arg *ja);
static int parse_args_for_encrypt(int argc, char *args[], struct job_arg *ja);
static int parse_args_for_decrypt(int argc, char *args[], struct job_arg *ja);
static int parse_args_for_concat(int argc, char *args[], struct job_arg *ja);
static int parse_args_for_priority(int argc, char *args[], struct job_arg *ja);
static int parse_args_for_compress(int argc, char *args[], struct job_arg *ja);
static int parse_args_for_decompress(int argc, char *args[],
				     struct job_arg *ja);

void print_usage(void)
{
	printf("Usage:\n"
		"jobctl [-h]\n"
		"jobctl [-r jobid]\n"
		"jobctl [-l]\n"
		"jobctl [-s jobid]\n"
		"jobctl [-e filename cipher key]\n"
		"jobctl [-d filename cipher key]\n"
		"jobctl [-z filename]\n"
		"jobctl [-u filename]\n"
		);
}

void print_help(void)
{
	print_usage();
	printf("\n");
	printf("Options description\n"
		"-r jobid\t removes a job\n"
		"-l\t\t lists all the jobs enqueued\n"
		"-s jobid\t\t gets the job status\n"
		"-e filename cipher key \t\t encrypts file\n"
		"-d filename cipher key \t\t decrypts file\n"
		"-z filename \t\t compresses file\n"
		"-u filename \t\t decompresses file\n"
		"-h\t\t prints the usage and description\n"
		);
}

void create_md5_hash(char *key_hash, const char *key, size_t keylen)
{
	MD5_CTX context;

	MD5_Init(&context);
	MD5_Update(&context, key, keylen);
	MD5_Final((unsigned char *)key_hash, &context);
}

int main(int argc, char *argv[])
{
	extern char *optarg;
	extern int errno;
	extern int opterr;
	int opt, op = -1; /* op denotes the jobctl operation e.g. list jobs */
	int end = 0;
	int count, err;
	struct job_arg ja;
	int rc;
	char **args;

	/* no arguments specified */
	if (argc == 1) {
		print_usage();
		exit(EXIT_FAILURE);
	}

	/* parse command line arguments */
	opterr = 0;
	while ((opt = getopt(argc, argv, "hlcdrsepzu")) != -1) {
		if (end || (optarg && *optarg == '-')) {
			printf("Too many options\n"
				"Please consult help: %s -h\n", argv[0]);
			exit(EXIT_FAILURE);
		}
		switch (opt) {
		case 'l':
			op = LIST;
			break;
		case 'r':
			op = REMOVE;
			break;
		case 's':
			op = STATUS;
			break;
		case 'e':
			op = ENCRYPT;
			break;
		case 'd':
			op = DECRYPT;
			break;
		case 'z':
			op = COMPRESS;
			break;
		case 'u':
			op = DECOMPRESS;
			break;
		case 'c':
			op = STRCONCAT;
			break;
		case 'p':
			op = CHPRIORITY;
			break;
		case 'h':
			print_help();
			exit(EXIT_SUCCESS);
			break;
		case '?':
			if (isprint(optopt))
				fprintf(stderr, "Invalid option -%c\n", optopt);
			else
				fprintf(stderr, "Invalid option \\x%x\n",
					optopt);
			exit(EXIT_FAILURE);
			break;
		default:
			print_usage();
			exit(EXIT_FAILURE);
		}
		++end;
	}
	if (op == -1) {
		fprintf(stderr, "Invalid set of option(s)/argument(s)\n"
			"Please consult help: %s -h\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	/* get the args of the op if exist */
	count = argc - 2;
	args = argv + 2;
	bzero(&ja, sizeof(ja));
	switch (op) {
	case LIST:
		err = parse_args_for_list(count, args, &ja);
		break;
	case REMOVE:
		err = parse_args_for_remove(count, args, &ja);
		break;
	case STATUS:
		err = parse_args_for_status(count, args, &ja);
		break;
	case ENCRYPT:
		err = parse_args_for_encrypt(count, args, &ja);
		break;
	case DECRYPT:
		err = parse_args_for_decrypt(count, args, &ja);
		break;
	case STRCONCAT:
		err = parse_args_for_concat(count, args, &ja);
		break;
	case CHPRIORITY:
		err = parse_args_for_priority(count, args, &ja);
		break;
	case COMPRESS:
		err = parse_args_for_compress(count, args, &ja);
		break;
	case DECOMPRESS:
		err = parse_args_for_decompress(count, args, &ja);
		break;
	default:
		err = 1;
		break;
	}
	if (err == 1) {
		fprintf(stderr, "Bad arguments\n");
		exit(EXIT_FAILURE);
	}
	if (err == 2)
		exit(EXIT_FAILURE);

	rc = syscall(__NR_submitjob, &ja, sizeof(ja));
	if (rc < 0) {
		if (ja.op == LIST) {
			free(((struct sj_job_list *)ja.arg)->list);
		} else if (ja.op == REMOVE) {
			fprintf(stderr, "Job %d doesnt exist\n",
				*(int *)ja.arg);
		} else if (ja.op == CHPRIORITY) {
			fprintf(stderr, "Priority not changed\n");
		} else if (ja.op == STATUS) {
			fprintf(stderr, "Invalid job %d\n", *(int *)ja.arg);
		} else if (ja.op == ENCRYPT) {
			perror("Encryption failed\n");
			free(((struct sj_job_encrypt *)ja.arg)->key);
		} else if (ja.op == DECRYPT) {
			perror("Decryption failed\n");
			free(((struct sj_job_encrypt *)ja.arg)->key);
		} else {
			fprintf(stderr, "syscall returned %d (errno=%d)\n)",
				rc, errno);
		}
		free(ja.arg);
		exit(EXIT_FAILURE);
	}
	if (rc == 0) {
		if (ja.op == LIST) {
			printf("%d jobs in queue\n", rc);
			free(((struct sj_job_list *)ja.arg)->list);
			free(ja.arg);
		} else if (ja.op == REMOVE) {
			printf("Job %d is removed\n", *((int *)ja.arg));
		} else if (ja.op == CHPRIORITY) {
			printf("Job priority\n");
		} else if (ja.op == STATUS) {
			printf("Job\t\tStatus\t\tError code\n");
			switch (((struct sj_job_status *)ja.arg)->status) {
			case INQUEUE:
				printf("%d\t\tINQUEUE\t\t%d\n",
				       ((struct sj_job_status *)ja.arg)->id,
				       ((struct sj_job_status *)ja.arg)->err);
				break;
			case INPROGRESS:
				printf("%d\t\tINPROGRESS\t\t%d\n",
				       ((struct sj_job_status *)ja.arg)->id,
				       ((struct sj_job_status *)ja.arg)->err);
				break;
			case COMPLETED:
				printf("%d\t\tCOMPLETED\t\t%d\n",
				       ((struct sj_job_status *)ja.arg)->id,
				       ((struct sj_job_status *)ja.arg)->err);
				if (((struct sj_job_status *)ja.arg)->err < 0)
					printf("%s\n", strerror(-1 * ((struct sj_job_status *)ja.arg)->err));
				break;
			default:
				printf("%d\t\t%d\t\t%d\n",
				       ((struct sj_job_status *)ja.arg)->id,
				       ((struct sj_job_status *)ja.arg)->status,
				       ((struct sj_job_status *)ja.arg)->err);
				break;
			}
			free(ja.arg);
		} else if (ja.op == ENCRYPT || ja.op == DECRYPT) {
			free(((struct sj_job_encrypt *)ja.arg)->key);
			free(ja.arg);
		} else if (ja.op == COMPRESS) {
			free(ja.arg);
		} else if (ja.op == DECOMPRESS) {
			free(ja.arg);
		} else {
			printf("Job submission failed."
				"syscall returned %d (errno=%d)\n", rc, errno);
		}
	} else {
		if (ja.op == LIST) {
			int i;
			struct sj_job *l = ((struct sj_job_list *)ja.arg)->list;

			printf("%d jobs in queue\n", rc);
			printf("Jobid\t\tJob\n");
			for (i = 0; i < rc; i++) {
				switch (l->op) {
				case ENCRYPT:
					printf("%d\t\tENCRYPT\n", l->id);
					break;
				case DECRYPT:
					printf("%d\t\tDECRYPT\n", l->id);
					break;
				case STRCONCAT:
					printf("%d\t\tCONCAT\n", l->id);
					break;
				case COMPRESS:
					printf("%d\t\tCOMPRESS\n", l->id);
					break;
				case DECOMPRESS:
					printf("%d\t\tDECOMPRESS\n", l->id);
					break;
				default:
					printf("%d\t\t%d\n", l->id, l->op);
					break;
				}
				l++;
			}
			free(((struct sj_job_list *)ja.arg)->list);
			free(ja.arg);
		} else {
			printf("[jobid=%d]\n", rc);
		}
	}

	return 0;
}

/* 0=> success, 1=>error, 2=>unimplemented */
int parse_args_for_concat(int argc, char *args[], struct job_arg *ja)
{
	char *str1, *str2;
	struct strconcat *op_arg;

	if (argc != 2)
		return 1;

	str1 = (char *)malloc(100);
	str2 = (char *)malloc(100);
	bzero(str1, 100);
	bzero(str2, 100);
	strcpy(str1, args[0]);
	strcpy(str2, args[1]);

	op_arg = (struct strconcat *)malloc(sizeof(struct strconcat));
	op_arg->str1 = str1;
	op_arg->str2 = str2;

	ja->op = STRCONCAT;
	ja->arg = op_arg;
	ja->priority = 3;

	return 0;
}

int parse_args_for_list(int argc, char *args[], struct job_arg *ja)
{
	struct sj_job_list *l;

	if (argc != 0)
		return 1;

	ja->op = LIST;
	ja->arg = (struct sj_job_list *)malloc(sizeof(struct sj_job_list));
	bzero(ja->arg, sizeof(struct sj_job_list));
	l = (struct sj_job_list *)ja->arg;
	l->list = (struct sj_job *)malloc(sizeof(struct sj_job) * 512);
	if (!l->list) {
		fprintf(stderr, "no mem\n");
		return 1;
	}
	bzero(l->list, sizeof(struct sj_job) * 512);
	ja->priority = 3;

	return 0;
}

int parse_args_for_remove(int argc, char *args[], struct job_arg *ja)
{
	int jobid;

	if (argc != 1)
		return 1;

	/* check if a number is >0 and <512*/
	jobid = atoi(args[0]);
	if ((!jobid && jobid < 0) || jobid > 512)
		return 1;
	ja->op = REMOVE;
	ja->arg = (int *)malloc(sizeof(int));
	*(int *)(ja->arg) = jobid;
	ja->priority = 3;

	return 0;
}

int parse_args_for_status(int argc, char *args[], struct job_arg *ja)
{
	int jobid;
	struct sj_job_status *st;

	if (argc != 1)
		return 1;

	/* check if a number is >0 and <512*/
	jobid = atoi(args[0]);
	if ((!jobid && jobid < 0) || jobid > 512)
		return 1;
	ja->op = STATUS;
	ja->arg = (struct sj_job_status *)malloc(sizeof(struct sj_job_status));
	st = (struct sj_job_status *)ja->arg;
	st->id = jobid;

	return 0;
}

int parse_args_for_encrypt(int argc, char *args[], struct job_arg *ja)
{
	char *arg1, *arg2, *arg3;
	char *keyhash;
	struct sj_job_encrypt *op_arg;

	if (argc != 3)
		return 1;
	arg1 = args[0];
	arg2 = args[1];
	arg3 = args[2];

	if (strcmp(arg2, "aes"))
		printf("%s Not Supported, Using default AES cipher\n", arg2);
	keyhash = malloc(16);
	create_md5_hash(keyhash, arg3, strlen(arg3));
	op_arg = (struct sj_job_encrypt *)malloc(sizeof(struct sj_job_encrypt));
	op_arg->file = arg1;
	op_arg->cipher = arg2;
	op_arg->key = keyhash;

	ja->op = ENCRYPT;
	ja->arg = op_arg;
	ja->priority = 3;
	return 0;
}

int parse_args_for_decrypt(int argc, char *args[], struct job_arg *ja)
{
	char *arg1, *arg2, *arg3;
	char *keyhash;
	struct sj_job_encrypt *op_arg;

	if (argc != 3)
		return 1;
	arg1 = args[0];
	arg2 = args[1];
	arg3 = args[2];

	if (strcmp(arg2, "aes"))
		printf("%s Not Supported, Using default AES cipher\n", arg2);

	keyhash = malloc(16);
	create_md5_hash(keyhash, arg3, strlen(arg3));

	op_arg = (struct sj_job_encrypt *)malloc(sizeof(struct sj_job_encrypt));
	op_arg->file = arg1;
	op_arg->cipher = arg2;
	op_arg->key = keyhash;

	ja->op = DECRYPT;
	ja->arg = op_arg;
	ja->priority = 3;
	return 0;
}

int parse_args_for_priority(int argc, char *args[], struct job_arg *ja)
{
	int jobid;
	int priority;

	if (argc != 2)
		return 1;
	jobid = atoi(args[0]);
	priority = atoi(args[1]);
	if ((!jobid && jobid < 0) || jobid > 512)
		return 1;
	if ((!priority && priority < 0) || priority > 3)
		return 1;
	ja->op = CHPRIORITY;
	ja->arg = (struct sj_job_priority *)malloc
		  (sizeof(struct sj_job_priority));
	((struct sj_job_priority *)ja->arg)->id = jobid;
	((struct sj_job_priority *)ja->arg)->priority = priority;

	return 0;
}

int parse_args_for_compress(int argc, char *args[], struct job_arg *ja)
{
	int size;
	char *path = NULL;

	if (argc != 1)
		return 1;

	ja->op = COMPRESS;
	size = strlen(args[0]);
	path = malloc(size + 1);
	memcpy(path, args[0], size + 1);
	ja->arg = path;
	ja->priority = 3;
	return 0;
}

int parse_args_for_decompress(int argc, char *args[], struct job_arg *ja)
{
	int size;
	char *path = NULL;

	if (argc != 1)
		return 1;

	ja->op = DECOMPRESS;
	size = strlen(args[0]);
	path = malloc(size + 1);
	memcpy(path, args[0], size + 1);
	ja->arg = path;
	ja->priority = 3;
	return 0;
}
