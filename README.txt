			Asynchronous producer consumer processing

Objects
--------------------------------------------------------------------------------
1. Job Queue
This queue stores all the jobs that the user wants to run. It has a max limit of
511 jobs. It is implemented using a linked list.

2. Consumer thread
This is a thread which is responsible for picking a job from queue and process
it and store the return code in an array to be picked up by the user later.
While the queue is empty, the thread sleeps. When a producer puts a job in an
empty queue, it wakes up the consumer thread to start dequeue the job queue and
process the jobs.

3. Producer system call
This is a system call sys_submitjob() which acts like a producer for the job
queue. It takes input a user request for a job, puts it in queue and returns a
jobid that it assigns to the job.


Jobid assignment
--------------------------------------------------------------------------------
We use a bitmap of size 512 ranging from 0 to 511 to assign a jobid to a job.
If a bit is set means that corresponding jobid bit is in use and vice versa.
The bit is set by the system call while putting a job in queue and is cleared
when the consumer is done processing it.

Error handling
--------------------------------------------------------------------------------
We use an array err_code to store the error codes of the jobs which are indexed
with jobid. The consumer thread after processing job writes the return code
returned by the job to the err_code indexed by the jobid.
Since the jobids are reusable, we prevent the duplicacy by having a jobs bitmap
of size 512. If the a bit corresponding to a jobid is set means that error code
stored in the err_code is valid and vice versa.

Priority change
--------------------------------------------------------------------------------
We allow to change the priority of the jobs while they are in job queue. Lower
number means higher priority. For the same priority, the jobs are processed in
order of FCFS.
When we increase the priority of the job, we remove it from the queue and push
it towards the head of the queue as close as possible and vice versa if we
decrease the priority.

Operation
--------------------------------------------------------------------------------
- User wanting to do some job, which requires huge waiting time, calls the
sys_submitjob() system call which takes in a job_arg struct as input parameter
defining a job and its arguments.

- The system call inside kernel decodes this job and transforms it to a
job_work_struct so that it could be enqueued.

- It then refers to the latest bit available in jid bitmap to get the jobid to
be assigned to this job. It also sets that bit to mark that that jobid is now in
use.

- It assigns a default priority of 3 to the job.

- It then puts the job in queue.

- The system call after enqueuing the job wakes up the consumer thread if the
queue initially was empty.

- The system call returns the jobid to the user for reference. The user can now
poll the jobid for its status.

- At the kernel side, consumer thread wakes up if it was sleeping and picks up
job at head of the queue. It updates a curr_job variable with the jobid it just
picked up. This means that this jobid is being currently run by the consumer

- After the consumer thread completes the processing of the job, it stores the
return the error code from job in the err_code array indexed at that jobid. It
then set the corresponding bit in jobs bitmap to mark that error code valid in
case polled by user. It also clears the corresponding bit in jid bitmap to say
that a new job can take up this jobid if needed.

- It then clears off the curr_job variable and heads for the next job if
available in queue. If not, it sleeps only ot be waken up by producer when the
next job gets enqueued.


Job list operation
--------------------------------------------------------------------------------
We support the list operation which enlists all the jobs in queue.
We take a lock on the queue and get the jobs at that point of time and return to
the user space in the buffer provided by the user.

Job status operation
--------------------------------------------------------------------------------
This operation is used to poll the status of a job given its jobid.
In order to determine that, we first lock the queue and look at the curr_job to
know if that job is currently running. If not, then we look in the queue to
determine if it is there in the queue. It not, then we check the jobs bitmap to
check if the job has completed. If not, then the job is invalidated and told
back to user.

Syscall Supported Operations:
-------------------------------------------------------------------------------
1. Encryption
./jobctl -e filename cipher key

Takes 3 command line args:
filename :  input file name to encrypt
cipher 	 :  cipher to be used for encyption(currently only aes is supported)
key	 :  key used to encrypt file

Output: "filename".enc on success

-It encrpyts the input file using CTR(AES) cipher, MD5 hash of key is
used to encrypt the data.
-Currently syscall supports only AES cipher to encrypt. But the syscall is
designed with extensibility in mind. New API can be added to syscall that
supports other cipher type.

Policy:
- Creates an encrypted file with name "filename".enc. Overwrites it if already
exists.
- If input file is empty, creates an output file with only preamble in it.
- If input file does not exist, job is not added to queue, error thrown to user
by producer.

2. Decryption
./jobctl -d filename".enc" cipher key
./jobctl -d filename cipher key

Takes 3 command line args:
filename :  input file name to decrypt
cipher 	 :  cipher to be used for decyption(currently only aes is supported)
key      :  key used to decrypt file

Output: Decrypted file with name "filename" on success

-It decrpyts the input file using CTR(AES) cipher, MD5 hash of "key" is
used to decrypt the data.
-Currently syscall supports only AES cipher to decrypt. But the syscall is
designed with extensibility in mind. New API can be added to syscall that
supports other cipher type.

Policy:
- Check the preamble stored in file and compare it with the MD5 hash of "key",
if mismatch throw -EACCES
- If input filename does not have ".enc" extension, then it overwrites the same
file, else it creates a new file removing ".enc" extension from "filename".
If file "filename" already exists, overwrite it.
- If input file does not exist, job is not added to queue, error thrown to user
by producer.

3. Compression
./jobctl -z filename

Takes 1 command line argument:
filename  :  Input file to compress

Output	:  Compressed file with name "filename.cmp" on success.

- It compresses input file using LZ4 compression algorithm and creates output
file "filename.cmp".
- It writes compressed buffer size to output file, then writes the actual
compresed data to output file for each input buffer.

Policy:
- If output file already exists, then overwrite it.
- If input file is empty, create an empty output file.
- If input file does not exist, job is not added to queue, error thrown to user
by producer. 

3. Decompression
./jobctl -u "filename.cmp"

Takes 1 command line argument:
filename  :  Input file to decompress

Output	:  Decompressed file with name "filename" on success.

- It compresses input file using LZ4 compression algorithm and creates output
file "filename.cmp".
- It writes compressed buffer size to output file, then writes the actual
compresed data to output file for each input buffer.

Policy:
- If input file does not have ".cmp" extension then throw -EINVAL.
- If output file already exists, then overwrite it.
- If input file is empty, create an empty output file.
- If input file does not exist, job is not added to queue, error thrown to user
by producer.
