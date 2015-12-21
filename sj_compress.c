#include <linux/fs.h>
#include <linux/file.h>
#include <linux/namei.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/lz4.h>

#include "sj_job.h"

int sj_compress_data(char *inbuf, size_t inlen, char **outbuf, size_t *outlen)
{
	int ret = 0;
	size_t bound = 0;
	void *wrkmem;

	wrkmem = kzalloc(LZ4_MEM_COMPRESS, GFP_KERNEL);
	if (!wrkmem || IS_ERR(wrkmem)) {
		ret = PTR_ERR(wrkmem);
		goto out;
	}
	bound = lz4_compressbound(inlen);
	*outbuf = kzalloc(bound, GFP_KERNEL);
	if (!*outbuf || IS_ERR(*outbuf)) {
		ret = PTR_ERR(*outbuf);
		goto out;
	}
	ret = lz4_compress(inbuf, inlen, *outbuf, outlen, wrkmem);
out:
	kfree(wrkmem);
	return ret;
}

int sj_decompress_data(char *inbuf, size_t inlen, char **outbuf, size_t *outlen)
{
	int ret = 0;

	*outbuf = kzalloc(2 * PAGE_SIZE, GFP_KERNEL);
	if (!*outbuf || IS_ERR(*outbuf)) {
		ret = PTR_ERR(*outbuf);
		goto out;
	}
	ret = lz4_decompress_unknownoutputsize(inbuf, inlen,
					       *outbuf, outlen);
out:
	return ret;
}

/*
 * Function to write to file. Not many checks as it is internally
 * done in vfs_write.
 */
int sj_comp_write_file(struct file *filp, void *buf, int len)
{
	mm_segment_t oldfs;
	int bytes;

	if (!S_ISREG(file_inode(filp)->i_mode))
		return -EINVAL;
	if (!filp->f_op->write)
		return -EIO;
	oldfs = get_fs();
	set_fs(KERNEL_DS);
	bytes = vfs_write(filp, (char *)buf, len, &filp->f_pos);
	set_fs(oldfs);

	return bytes;
}

/*
 * Function to read from file. Not many checks as it is internally
 * done in vfs_read.
 */
int sj_comp_read_file(struct file *filp, void *buf, int len)
{
	mm_segment_t oldfs;
	int bytes;
	int size;

	if (!S_ISREG(file_inode(filp)->i_mode))
		return -EINVAL;
	size = i_size_read(file_inode(filp));
	if (size <= 0)
		return -EINVAL;

	if (!filp->f_op->read)
		return -EIO;

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	bytes = vfs_read(filp, buf, len, &filp->f_pos);
	set_fs(oldfs);
	return bytes;
}

/*
 * Unlinks file in case of error.
 * No error checking done so actual error can be
 * returned to the user.
 */
void sj_comp_unlink_file(struct file *filp)
{
	struct dentry *dentry = filp->f_path.dentry;
	struct dentry *p_dentry = dget_parent(dentry);

	mutex_lock(&p_dentry->d_inode->i_mutex);
	vfs_unlink(p_dentry->d_inode, dentry, NULL);
	mutex_unlock(&p_dentry->d_inode->i_mutex);
}

int sj_comp_rename_file(struct file *oldfilp, struct file *newfilp)
{
	int ret = 0;

	struct dentry *dentry = oldfilp->f_path.dentry;
	struct dentry *old_dentry = dget_parent(dentry);
	struct dentry *new_dentry = dget_parent(newfilp->f_path.dentry);

	ret = vfs_rename(old_dentry->d_inode, dentry, new_dentry->d_inode,
			 newfilp->f_path.dentry, NULL, 0);

	return ret;
}

/*
 * Creates new file with user and group id as of base file
 * and returns handle to new file as out parameter newfilp.
 * Permission will be later changed to match input file permissions.
 */
int sj_comp_create_tmp_file(struct file *basefilp, struct file **newfilp)
{
	struct inode *n_inode;
	struct inode *b_inode = file_inode(basefilp);
	struct dentry *base_dentry = basefilp->f_path.dentry;
	const char *ext = ".tmp";
	size_t len = 0;
	char *tmpfile = NULL;
	const unsigned char *name = base_dentry->d_name.name;

	len = strlen(name) + strlen(ext)  + 1;
	tmpfile = kzalloc(len, GFP_KERNEL);
	memcpy(tmpfile, name, strlen(name));
	memcpy(tmpfile + strlen(name), ext, strlen(ext) + 1);
	*newfilp  = filp_open(tmpfile, O_RDWR | O_CREAT, b_inode->i_mode);
	kfree(tmpfile);
	if (!(*newfilp))
		return -EINVAL;
	if (IS_ERR(*newfilp))
		return  PTR_ERR(*newfilp);
	n_inode = file_inode(*newfilp);
	n_inode->i_uid = b_inode->i_uid;
	n_inode->i_gid = b_inode->i_gid;

	(*newfilp)->f_pos = 0;

	return 0;
}

int __sj_decompress_file(struct file *i_filp, struct file *t_filp)
{
	size_t bytes_write = 2 * PAGE_SIZE;
	size_t bytes_read = 0;
	int size = 0;
	int ret = 0;
	char *inbuf = NULL;
	char *outbuf = NULL;
	int chunk_size = 0;

	inbuf = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!inbuf || IS_ERR(inbuf)) {
		ret = PTR_ERR(inbuf);
		goto err;
	}
	size = i_size_read(file_inode(i_filp));

	if (size <= 0)
		goto err;

	while (size > 0) {
		bytes_read = sj_comp_read_file(i_filp, &chunk_size,
					       sizeof(int));
		if (bytes_read != sizeof(int)) {
			ret = -EIO;
			goto err;
		}
		bytes_read = sj_comp_read_file(i_filp, inbuf, chunk_size);
		if (bytes_read < 0) {
			ret = bytes_read;
			goto err;
		}
		ret = sj_decompress_data(inbuf, chunk_size, &outbuf,
					 &bytes_write);
		if (ret < 0) {
			kfree(outbuf);
			goto err;
		}
		ret = sj_comp_write_file(t_filp, outbuf, bytes_write);
		if (ret < 0) {
			kfree(outbuf);
			goto err;
		}
		kfree(outbuf);
		size = size - bytes_read - sizeof(int);
	}
err:
	return ret;
}

int __sj_compress_file(struct file *i_filp, struct file *t_filp)
{
	size_t bytes_write = 0;
	size_t bytes_read = 0;
	int size = 0;
	int ret = 0;
	char *inbuf = NULL;
	char *outbuf = NULL;

	inbuf = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!inbuf || IS_ERR(inbuf)) {
		ret = PTR_ERR(inbuf);
		goto err;
	}
	size = i_size_read(file_inode(i_filp));

	if (size <= 0)
		goto err;

	while (size > 0) {
		bytes_read = sj_comp_read_file(i_filp, inbuf, PAGE_SIZE);
		if (bytes_read < 0) {
			ret = bytes_read;
			goto err;
		}
		ret = sj_compress_data(inbuf, bytes_read, &outbuf,
				       &bytes_write);
		if (ret < 0) {
			kfree(outbuf);
			goto err;
		}
		ret = sj_comp_write_file(t_filp, &bytes_write, sizeof(int));
		if (ret < 0) {
			kfree(outbuf);
			goto err;
		}
		ret = sj_comp_write_file(t_filp, outbuf, bytes_write);
		if (ret < 0) {
			kfree(outbuf);
			goto err;
		}
		kfree(outbuf);
		size = size - bytes_read;
	}
err:
	return ret;
}

/*
 * It validates the input and output files and finally compresss
 * or decompresses the file.
 */

int sj_compress_file(const char *infile, const char *outfile,
		     unsigned int compress)
{
	int ret = 0;
	int out_creat = 0;
	struct file *i_filp, *o_filp;
	struct file *t_filp = NULL;

	i_filp = filp_open(infile, O_RDONLY, 0);
	if (!i_filp || IS_ERR(i_filp)) {
		ret =  PTR_ERR(i_filp);
		goto out;
	}

	o_filp = filp_open(outfile, O_RDWR, 0);
	if (!o_filp || IS_ERR(o_filp))
		out_creat = 1;

	if (out_creat) {
		o_filp = filp_open(outfile, O_RDWR | O_CREAT,
				   file_inode(i_filp)->i_mode);
		if (!o_filp) {
			out_creat = 0;
			ret = -EINVAL;
			goto err_ifile;
		}
		if (IS_ERR(o_filp)) {
			out_creat = 0;
			ret = PTR_ERR(o_filp);
			goto err_ifile;
		}
	}
	ret = sj_comp_create_tmp_file(o_filp, &t_filp);
	if (ret < 0)
		goto err_ofile;

	i_filp->f_pos = 0;
	o_filp->f_pos = 0;
	if (compress) {
		ret = __sj_compress_file(i_filp, t_filp);
		if (ret < 0)
			goto err;
	} else {
		ret = __sj_decompress_file(i_filp, t_filp);
		if (ret < 0)
			goto err;
	}
err:
	if (ret >= 0)
		ret = sj_comp_rename_file(t_filp, o_filp);
	else
		sj_comp_unlink_file(t_filp);
	filp_close(t_filp, NULL);
err_ofile:
/* If there is error and outfile is created unlink it */
	if (ret < 0 && out_creat)
		sj_comp_unlink_file(o_filp);
	filp_close(o_filp, NULL);
err_ifile:
	filp_close(i_filp, NULL);
out:
	return ret;
}
