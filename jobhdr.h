#define ENCRYPT		1
#define DECRYPT		2
#define STRCONCAT	3
#define LIST		4
#define REMOVE		5
#define STATUS		6
#define CHPRIORITY	7
#define COMPRESS	8
#define DECOMPRESS  9

#define INQUEUE		1
#define INPROGRESS	2
#define COMPLETED	3

/* args struct for a generic job */
struct job_arg {
	int op;
	void *arg;
	int priority;
};

/* args struct for string concatenation */
struct strconcat {
	char *str1;
	char *str2;
};

struct sj_job_concat {
	char *file1;
	char *file2;
};

struct sj_job_encrypt {
	char *file;
	char *cipher;
	char *key;
};

struct sj_job {
	int id;
	int op;
};

struct sj_job_list {
	struct sj_job *list;
	int count;
};

struct sj_job_status {
	int id;
	int status;
	int err;
};

struct sj_job_priority {
	int id;
	int priority;
};
