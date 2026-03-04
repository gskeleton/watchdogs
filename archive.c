#include  "utils.h"
#include  "archive.h"
#include  "curl.h"
#include  "debug.h"
#include  "units.h"

static void
arch_extraction_path(const char* dest, const char* path,
	char* out, size_t out_size)
{
	/* Validate input parameters */
	if (dest == NULL) {
		pr_error(stdout, "arch_extraction_path: dest is NULL");
		return;
	} /* if */
	
	if (path == NULL) {
		pr_error(stdout, "arch_extraction_path: path is NULL");
		return;
	} /* if */
	
	if (out == NULL) {
		pr_error(stdout, "arch_extraction_path: out buffer is NULL");
		return;
	} /* if */
	
	if (out_size < 1) {
		pr_error(stdout, "arch_extraction_path: out_size is invalid");
		return;
	} /* if */
	
	/* Check destination path conditions */
	if (strlen(dest) < 1 ||
		strcmp(dest, ".") == 0 ||
		strcmp(dest, "root") == 0)
	{
		/* Use original path when dest is root-like */
		(void)snprintf(out, out_size, "%s", path);
	} else {
		/* Check if path already includes dest */
		if (strncmp(path, dest, strlen(dest)) == 0) {
			/* Path already has dest prefix */
			(void)snprintf(out, out_size, "%s", path);
		} else {
			/* Combine dest and path */
			(void)snprintf(out, out_size, "%s" "%s" "%s",
				dest, _PATH_STR_SEP_POSIX, path);
		} /* if */
	} /* if */
} /* arch_extraction_path */

static int
arch_copy_data(struct archive* ar, struct archive* aw)
{
	size_t		 size = 0;
	la_int64_t	 offset = 0;
	int		 ret = -2;
	int		 block_count = 0;
	const void* buffer = NULL;
	
	/* Validate archive pointers */
	if (ar == NULL) {
		pr_error(stdout, "arch_copy_data: source archive is NULL");
		return (ARCHIVE_FATAL);
	} /* if */
	
	if (aw == NULL) {
		pr_error(stdout, "arch_copy_data: destination archive is NULL");
		return (ARCHIVE_FATAL);
	} /* if */

	/* Copy data blocks until EOF */
	while (true) {
		/* Read next data block */
		ret = archive_read_data_block(ar, &buffer, &size, &offset);
		block_count++;
		
		/* Check for end of archive */
		if (ret == ARCHIVE_EOF) {
			pr_info(stdout, "arch_copy_data: reached EOF after %d blocks", block_count);
			return (ARCHIVE_OK);
		} /* if */
		
		/* Handle read errors */
		if (ret != ARCHIVE_OK) {
			pr_warning(stdout,
				"arch_copy_data getting error "
				"(read error at block %d): %s",
				block_count, archive_error_string(ar));
			return (ret);
		} /* if */

		/* Verify data was read */
		if (buffer == NULL) {
			pr_warning(stdout, "arch_copy_data: buffer is NULL at block %d", block_count);
			continue;
		} /* if */
		
		if (size == 0) {
			pr_warning(stdout, "arch_copy_data: zero size block at block %d", block_count);
			continue;
		} /* if */

		/* Write data block */
		ret = archive_write_data_block(aw, buffer, size, offset);
		if (ret != ARCHIVE_OK) {
			pr_warning(stdout,
				"arch_copy_data getting error "
				"(write error at block %d): %s",
				block_count, archive_error_string(aw));
			return (ret);
		} /* if */
		
		/* Log progress periodically */
		if (block_count % 100 == 0) {
			;
		} /* if */
	} /* while */
	
	/* Should never reach here */
	return (ARCHIVE_OK);
} /* arch_copy_data */

int
compress_to_archive(const char* archive_path,
	const char** file_paths,
	int raw_num_files,
	CompressionFormat format)
{
	struct archive* archive = NULL;
	struct archive_entry* entry = NULL;
	char		 buffer[DOG_MORE_MAX_PATH] = {0};
	size_t		 len = 0;
	int		 fd = -1;
	int		 ret = 0;
	int		 success_count = 0;
	int		 error_count = 0;
	struct stat	 fd_stat;
	
	/* Validate input parameters */
	if (archive_path == NULL) {
		pr_error(stdout, "compress_to_archive: archive_path is NULL");
		minimal_debugging();
		return (-1);
	} /* if */
	
	if (file_paths == NULL) {
		pr_error(stdout, "compress_to_archive: file_paths is NULL");
		minimal_debugging();
		return (-1);
	} /* if */
	
	if (raw_num_files <= 0) {
		pr_error(stdout, "compress_to_archive: raw_num_files is %d", raw_num_files);
		minimal_debugging();
		return (-1);
	} /* if */

	/* Create new archive writer */
	archive = archive_write_new();
	if (archive == NULL) {
		pr_error(stdout, "failed to creating archive object..");
		minimal_debugging();
		return (-1);
	} /* if */

	/* Set format based on compression type */
	switch (format) {
	case COMPRESS_ZIP:
		archive_write_set_format_zip(archive);
		break;

	case COMPRESS_TAR:
		archive_write_set_format_pax_restricted(archive);
		break;

	case COMPRESS_TAR_GZ:
		archive_write_set_format_pax_restricted(archive);
		archive_write_add_filter_gzip(archive);
		break;

	case COMPRESS_TAR_BZ2:
		archive_write_set_format_pax_restricted(archive);
		archive_write_add_filter_bzip2(archive);
		break;

	case COMPRESS_TAR_XZ:
		archive_write_set_format_pax_restricted(archive);
		archive_write_add_filter_xz(archive);
		break;

	default:
		pr_error(stdout,
			"unsupport compression format %d.. default.: zip, tar, gz, bz2, xz",
			format);
		archive_write_free(archive);
		return (-1);
	} /* switch */

	/* Open output archive file */
	ret = archive_write_open_filename(archive, archive_path);
	if (ret != ARCHIVE_OK) {
		pr_error(stdout, "failed to open the archive: %s",
			archive_path);
		minimal_debugging();
		archive_write_free(archive);
		return (-1);
	} /* if */

	/* Process each input file */
	for (int i = 0; i < raw_num_files; i++) {
		/* Get current filename */
		const char* filename = file_paths[i];
		
		/* Validate filename */
		if (filename == NULL) {
			pr_error(stdout, "compress_to_archive: file_paths[%d] is NULL", i);
			error_count++;
			continue;
		} /* if */

		/* Open file */
		fd = open(filename, O_RDONLY);
		if (fd < 0) {
			pr_error(stdout, "failed to open the file: %s..: %s",
				filename, strerror(errno));
			minimal_debugging();
			ret = -1;
			error_count++;
			continue;
		} /* if */

		/* Get file statistics */
		if (fstat(fd, &fd_stat) != 0) {
			pr_error(stdout, "failed to fstat file: %s..: %s",
				filename, strerror(errno));
			minimal_debugging();
			close(fd);
			ret = -1;
			error_count++;
			continue;
		} /* if */

		/* Check if it's a regular file */
		if (!S_ISREG(fd_stat.st_mode)) {
			if (S_ISDIR(fd_stat.st_mode)) {
				pr_info(stdout, "compress_to_archive: %s is a directory", filename);
				close(fd);
				ret = -2;
				goto fallback;
			} /* if */
			
			pr_warning(stdout, "the %s is not a regular file!..", filename);
			minimal_debugging();
			close(fd);
			ret = -1;
			error_count++;
			continue;
		} /* if */

		/* Create archive entry for this file */
		entry = archive_entry_new();
		if (entry == NULL) {
			pr_error(stdout,
				"failed to creating archive entry for: %s",
				filename);
			minimal_debugging();
			close(fd);
			ret = -1;
			error_count++;
			continue;
		} /* if */

		/* Set entry metadata */
		archive_entry_set_pathname(entry, filename);
		archive_entry_set_size(entry, fd_stat.st_size);
		archive_entry_set_filetype(entry, AE_IFREG);
		archive_entry_set_perm(entry, fd_stat.st_mode);
		archive_entry_set_mtime(entry, fd_stat.st_mtime, 0);
		archive_entry_set_atime(entry, fd_stat.st_atime, 0);
		archive_entry_set_ctime(entry, fd_stat.st_ctime, 0);

		/* Write entry header */
		ret = archive_write_header(archive, entry);
		if (ret != ARCHIVE_OK) {
			pr_error(stdout,
				"failed to write header for: %s..: %s",
				filename, archive_error_string(archive));
			minimal_debugging();
			archive_entry_free(entry);
			close(fd);
			ret = -1;
			error_count++;
			continue;
		} /* if */

		/* Write file data in chunks */
		while ((len = read(fd, buffer, sizeof(buffer))) > 0) {
			ssize_t	 written = archive_write_data(archive, buffer, len);

			if (written < 0) {
				pr_error(stdout,
					"failed to write data for: %s..: %s",
					filename, archive_error_string(archive));
				minimal_debugging();
				ret = -1;
				error_count++;
				break;
			} /* if */
			
			if (written != (ssize_t)len) {
				pr_error(stdout, "partial write for: %s (wrote %zd of %zu)",
					filename, written, len);
				minimal_debugging();
				ret = -1;
				error_count++;
				break;
			} /* if */
		} /* while */

		/* Check for read errors */
		if (len < 0) {
			pr_error(stdout,
				"failed to trying read file: %s..: %s",
				filename, strerror(errno));
			minimal_debugging();
			ret = -1;
			error_count++;
		} else {
			/* File processed successfully */
			success_count++;
		} /* if */

		/* Cleanup for this file */
		close(fd);
		archive_entry_free(entry);
		entry = NULL;

		/* Check if we should abort */
		if (ret != 0 && ret != -2) {
			pr_warning(stdout, "compress_to_archive: aborting due to error");
			break;
		} /* if */
	} /* for */

	/* Close and free archive */
	archive_write_close(archive);
	archive_write_free(archive);

fallback:
	/* If a directory was found, fall back to directory compression */
	if (ret == -2) {
		ret = compress_directory(archive_path, file_paths[0], format);
	} /* if */
	
	return (ret);
} /* compress_to_archive */

int
dog_path_recursive(struct archive* archive, const char* root, const char* path)
{
	struct archive_entry* entry = NULL;
	struct stat		 path_stat;
	char			 full_path[DOG_MAX_PATH * 2] = {0};
	int			 fd = -1;
	struct stat		 fd_stat;
	size_t			 read_len = 0;
	int			 total_bytes = 0;
	char			 buffer[DOG_MORE_MAX_PATH] = {0};
	DIR* dirp = NULL;
	struct dirent* dent = NULL;
	char			 child_path[DOG_MAX_PATH] = {0};
	int			 file_count = 0;
	int			 dir_count = 0;
	
	/* Validate input parameters */
	if (archive == NULL) {
		pr_error(stdout, "dog_path_recursive: archive is NULL");
		minimal_debugging();
		return (-1);
	} /* if */
	
	if (root == NULL) {
		pr_error(stdout, "dog_path_recursive: root is NULL");
		minimal_debugging();
		return (-1);
	} /* if */
	
	if (path == NULL) {
		pr_error(stdout, "dog_path_recursive: path is NULL");
		minimal_debugging();
		return (-1);
	} /* if */

	/* Build full path */
	(void)snprintf(full_path, sizeof(full_path),
		"%s" "%s" "%s", root, _PATH_STR_SEP_POSIX, path);

#ifdef DOG_WINDOWS
	if (stat(full_path, &path_stat) != 0) {
		pr_error(stdout, "stat failed..: %s..: %s",
			full_path, strerror(errno));
		minimal_debugging();
		return (-1);
	} /* if */
#else
	/* Use lstat to avoid following symlinks */
	if (lstat(full_path, &path_stat) != 0) {
		pr_error(stdout, "lstat failed..: %s..: %s",
			full_path, strerror(errno));
		minimal_debugging();
		return (-1);
	} /* if */
#endif

	/* Handle regular files */
	if (S_ISREG(path_stat.st_mode)) {
		file_count++;
		
#ifdef DOG_WINDOWS
		fd = open(full_path, O_RDONLY | O_BINARY);
#else
#ifdef O_NOFOLLOW
#ifdef O_CLOEXEC
		fd = open(full_path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
#else
		fd = open(full_path, O_RDONLY | O_NOFOLLOW);
#endif
#else
#ifdef O_CLOEXEC
		fd = open(full_path, O_RDONLY | O_CLOEXEC);
#else
		fd = open(full_path, O_RDONLY);
#endif
#endif
#endif

		if (fd == -1) {
			pr_error(stdout, "open failed..: %s..: %s",
				full_path, strerror(errno));
			minimal_debugging();
			return (-1);
		} /* if */

		/* Verify file didn't change during processing */
		if (fstat(fd, &fd_stat) != 0) {
			pr_error(stdout, "fstat failed..: %s..: %s",
				full_path, strerror(errno));
			minimal_debugging();
			close(fd);
			return (-1);
		} /* if */

		/* Compare inode and device */
		if (path_stat.st_ino != fd_stat.st_ino ||
			path_stat.st_dev != fd_stat.st_dev) {
			pr_warning(stdout,
				"the %s changes during processing..",
				full_path);
			minimal_debugging();
			close(fd);
			return (-1);
		} /* if */

		path_stat = fd_stat;

		/* Create archive entry */
		entry = archive_entry_new();
		if (!entry) {
			pr_error(stdout,
				"failed to creating archive entry for: %s",
				full_path);
			minimal_debugging();
			close(fd);
			return (-1);
		} /* if */

		archive_entry_set_pathname(entry, path);
		archive_entry_copy_stat(entry, &path_stat);

		/* Write header */
		if (archive_write_header(archive, entry) != ARCHIVE_OK) {
			pr_error(stdout, "archive_write_header failed..: %s",
				archive_error_string(archive));
			minimal_debugging();
			archive_entry_free(entry);
			close(fd);
			return (-1);
		} /* if */

		/* Write data in chunks */
		while ((read_len = read(fd, buffer, sizeof(buffer))) > 0) {
			ssize_t written = archive_write_data(archive, buffer, read_len);
			
			if (written < 0) {
				pr_error(stdout,
					"archive_write_data failed..: %s",
					archive_error_string(archive));
				minimal_debugging();
				archive_entry_free(entry);
				close(fd);
				return (-1);
			} /* if */
			
			total_bytes += written;
		} /* while */

		/* Check for read errors */
		if (read_len < 0) {
			pr_error(stdout, "failed to read..: %s..: %s",
				full_path, strerror(errno));
			minimal_debugging();
		} /* if */

		close(fd);
		archive_entry_free(entry);
		return ((read_len < 0) ? -1 : 0);
	} /* if */

	/* Handle directories */
	if (S_ISDIR(path_stat.st_mode)) {
		dir_count++;
		
		/* Create directory entry */
		entry = archive_entry_new();
		if (!entry) {
			pr_error(stdout,
				"failed to creating archive entry for: %s", full_path);
			minimal_debugging();
			return (-1);
		} /* if */

		archive_entry_set_pathname(entry, path);
		archive_entry_copy_stat(entry, &path_stat);

		/* Write directory header */
		if (archive_write_header(archive, entry) != ARCHIVE_OK) {
			pr_error(stdout, "archive_write_header failed..: %s",
				archive_error_string(archive));
			minimal_debugging();
			archive_entry_free(entry);
			return (-1);
		} /* if */

		archive_entry_free(entry);

		/* Recursively process directory contents */
		dirp = opendir(full_path);
		if (!dirp) {
			pr_error(stdout, "failed to opendir: %s..: %s",
				full_path, strerror(errno));
			minimal_debugging();
			return (-1);
		} /* if */

		/* Iterate through directory entries */
		while ((dent = readdir(dirp)) != NULL) {
			/* Skip . and .. entries */
			if (dog_dot_or_dotdot(dent->d_name)) {
				continue;
			} /* if */

			/* Build child path */
			(void)snprintf(child_path, sizeof(child_path),
				"%s" "%s" "%s",
				path, _PATH_STR_SEP_POSIX, dent->d_name);

			/* Recursively process child */
			if (dog_path_recursive(archive, root, child_path) != 0) {
				pr_error(stdout, "dog_path_recursive: failed to process: %s", child_path);
				closedir(dirp);
				return (-1);
			} /* if */
		} /* while */

		closedir(dirp);
	} /* if */
	
	/* Handle other file types */
	if (!S_ISREG(path_stat.st_mode) && !S_ISDIR(path_stat.st_mode)) {
		pr_warning(stdout, "dog_path_recursive: skipping special file: %s (mode: 0%o)",
			full_path, path_stat.st_mode);
	} /* if */

	return (0);
} /* dog_path_recursive */

int
compress_directory(const char* archive_path,
	const char* dir_path,
	CompressionFormat format)
{
	struct archive* a = NULL;
	int		 ret = 0;
	int		 retry_count = 0;
	const int	 max_retries = 3;
	
	/* Validate input parameters */
	if (archive_path == NULL) {
		pr_error(stdout, "compress_directory: archive_path is NULL");
		return (-1);
	} /* if */
	
	if (dir_path == NULL) {
		pr_error(stdout, "compress_directory: dir_path is NULL");
		return (-1);
	} /* if */

	/* Create archive writer */
	a = archive_write_new();
	if (!a) {
		pr_error(stdout, "compress_directory: failed to create archive");
		return (-1);
	} /* if */

	/* Set compression format based on type */
	switch (format) {
	case COMPRESS_ZIP:
		archive_write_set_format_zip(a);
		break;

	case COMPRESS_TAR:
		archive_write_set_format_pax_restricted(a);
		break;

	case COMPRESS_TAR_GZ:
		archive_write_set_format_pax_restricted(a);
		archive_write_add_filter_gzip(a);
		break;

	case COMPRESS_TAR_BZ2:
		archive_write_set_format_pax_restricted(a);
		archive_write_add_filter_bzip2(a);
		break;

	case COMPRESS_TAR_XZ:
		archive_write_set_format_pax_restricted(a);
		archive_write_add_filter_xz(a);
		break;

	default:
		pr_error(stdout,
			"unsupport compression format %d.. default.: zip, tar, gz, bz2, xz",
			format);
		archive_write_free(a);
		return (-1);
	} /* switch */

	/* Open output file with retry logic */
	for (retry_count = 0; retry_count < max_retries; retry_count++) {
		if (retry_count > 0) {
			pr_info(stdout, "compress_directory: retry %d/%d for: %s", 
				retry_count, max_retries, archive_path);
		} /* if */
		
		ret = archive_write_open_filename(a, archive_path);
		if (ret == ARCHIVE_OK) {
			break;
		} /* if */
		
		/* Wait before retry */
		if (retry_count < max_retries - 1) {
			#ifdef DOG_WINDOWS
			Sleep(100);
			#else
			usleep(100000);
			#endif
		} /* if */
	} /* for */
	
	if (ret != ARCHIVE_OK) {
		pr_error(stdout, "failed to open the archive after %d retries: %s",
			max_retries, archive_path);
		minimal_debugging();
		archive_write_free(a);
		return (-1);
	} /* if */

	/* Recursively add all files from directory */
	ret = dog_path_recursive(a, dir_path, "");
	
	/* Check result */
	if (ret != 0) {
		pr_error(stdout, "compress_directory: failed to add files from: %s", dir_path);
	} /* if */

	/* Cleanup */
	archive_write_close(a);
	archive_write_free(a);
	
	return (ret);
} /* compress_directory */

int
dog_extract_tar(const char* tar_path, const char* entry_dest)
{
	int		 r = 0;
	int		 flags = 0;
	int		 entry_count = 0;
	int		 error_count = 0;
	struct archive* a = NULL;
	struct archive* ext = NULL;
	struct archive_entry* entry = NULL;
	
	/* Validate input */
	if (tar_path == NULL) {
		pr_error(stdout, "dog_extract_tar: tar_path is NULL");
		return (-1);
	} /* if */

	/* Set extraction flags */
	flags = ARCHIVE_EXTRACT_TIME |
		ARCHIVE_EXTRACT_PERM |
		ARCHIVE_EXTRACT_ACL |
		ARCHIVE_EXTRACT_FFLAGS;

	/* Initialize read archive */
	a = archive_read_new();
	if (a == NULL) {
		pr_error(stdout, "dog_extract_tar: failed to create read archive");
		return (-1);
	} /* if */
	
	archive_read_support_format_all(a);
	archive_read_support_filter_all(a);

	/* Initialize write disk archive */
	ext = archive_write_disk_new();
	if (ext == NULL) {
		pr_error(stdout, "dog_extract_tar: failed to create write disk archive");
		archive_read_free(a);
		return (-1);
	} /* if */
	
	archive_write_disk_set_options(ext, flags);
	archive_write_disk_set_standard_lookup(ext);

	/* Open tar file with retry */
	r = archive_read_open_filename(a, tar_path, 10240);
	if (r != ARCHIVE_OK) {
		pr_error(stdout, "failed to opening the archive: %s..: %s",
			tar_path, archive_error_string(a));
		minimal_debugging();
		archive_read_free(a);
		archive_write_free(ext);
		return (-1);
	} /* if */

	/* Process each entry in the archive */
	while (true) {
		/* Read next header */
		r = archive_read_next_header(a, &entry);
		
		/* Check for end of archive */
		if (r == ARCHIVE_EOF) {
			pr_info(stdout, "dog_extract_tar: reached EOF after %d entries", entry_count);
			break;
		} /* if */
		
		/* Handle header read errors */
		if (r != ARCHIVE_OK) {
			pr_error(stdout, "failed to reading header: %s..: %s",
				tar_path, archive_error_string(a));
			minimal_debugging();
			error_count++;
			continue;
		} /* if */

		/* Get entry path */
		const char* entry_path = archive_entry_pathname(entry);
		if (entry_path == NULL) {
			pr_warning(stdout, "dog_extract_tar: entry with NULL pathname");
			continue;
		} /* if */
		
		entry_count++;

#if defined(_DBG_PRINT)
		/* Print extraction progress */
		char pbuf[strlen(entry_path) + 30 + 1];
		int len = snprintf(pbuf, sizeof(pbuf),
			" * Extracting: %s\n", entry_path);
		fwrite(pbuf, 1, len, stdout);
		fflush(stdout);
#endif
		
		/* Adjust extraction path if destination specified */
		if (entry_dest != NULL && strlen(entry_dest) > 0) {
			char	 entry_new_path[1024] = {0};
			
			/* Ensure destination directory exists */
			dog_mkdir_recursive(entry_dest);
			
			/* Build new path */
			(void)snprintf(entry_new_path, sizeof(entry_new_path),
				"%s" "%s" "%s", entry_dest,
				_PATH_STR_SEP_POSIX, entry_path);
			
			/* Update entry path */
			archive_entry_set_pathname(entry, entry_new_path);
		} /* if */

		/* Write header */
		r = archive_write_header(ext, entry);
		if (r != ARCHIVE_OK) {
			pr_error(stdout,
				"failed to writing header for: %s..: %s",
				entry_path, archive_error_string(ext));
			minimal_debugging();
			error_count++;
			continue;
		} /* if */
		
		/* Copy data */
		r = arch_copy_data(a, ext);
		if (r != ARCHIVE_OK && r != ARCHIVE_EOF) {
			pr_error(stdout, "error to copy data for: %s (error: %d)",
				entry_path, r);
			minimal_debugging();
			error_count++;
		} /* if */

		/* Finish entry */
		r = archive_write_finish_entry(ext);
		if (r != ARCHIVE_OK) {
			pr_error(stdout,
				"failed to finishing entry: %s..: %s",
				entry_path, archive_error_string(ext));
			minimal_debugging();
			error_count++;
		} /* if */
	} /* while */

	/* Cleanup */
	archive_read_close(a);
	archive_read_free(a);
	archive_write_close(ext);
	archive_write_free(ext);

	return (error_count > 0 ? -1 : 0);
} /* dog_extract_tar */

static int
extract_zip_entry(struct archive* archive_read,
	struct archive* archive_write,
	struct archive_entry* item)
{
	int		 ret = 0;
	int		 block_count = 0;
	int		 total_bytes = 0;
	const void* buffer = NULL;
	size_t		 size = 0;
	la_int64_t	 offset = 0;
	const char*	 entry_path = NULL;
	
	/* Validate input */
	if (archive_read == NULL) {
		pr_error(stdout, "extract_zip_entry: archive_read is NULL");
		return (-1);
	} /* if */
	
	if (archive_write == NULL) {
		pr_error(stdout, "extract_zip_entry: archive_write is NULL");
		return (-1);
	} /* if */
	
	if (item == NULL) {
		pr_error(stdout, "extract_zip_entry: item is NULL");
		return (-1);
	} /* if */
	
	/* Get entry path for logging */
	entry_path = archive_entry_pathname(item);
	if (entry_path == NULL) {
		entry_path = "(unknown)";
	} /* if */

	/* Write header */
	ret = archive_write_header(archive_write, item);
	if (ret != ARCHIVE_OK) {
		pr_error(stdout, "failed to write header for %s: %s",
			entry_path, archive_error_string(archive_write));
		minimal_debugging();
		return (-1);
	} /* if */

	/* Copy data blocks */
	while (true) {
		/* Read next data block */
		ret = archive_read_data_block(archive_read, &buffer,
			&size, &offset);
		block_count++;
		
		/* Check for end of data */
		if (ret == ARCHIVE_EOF) {
			pr_info(stdout, "extract_zip_entry: reached EOF for %s after %d blocks", 
				entry_path, block_count);
			break;
		} /* if */
		
		/* Handle read errors */
		if (ret < ARCHIVE_OK) {
			pr_error(stdout, "failed to read data for %s at block %d: %s",
				entry_path, block_count, archive_error_string(archive_write));
			minimal_debugging();
			return (-2);
		} /* if */
		
		/* Validate data */
		if (buffer == NULL) {
			pr_warning(stdout, "extract_zip_entry: NULL buffer at block %d for %s", 
				block_count, entry_path);
			continue;
		} /* if */
		
		if (size == 0) {
			pr_warning(stdout, "extract_zip_entry: zero size at block %d for %s", 
				block_count, entry_path);
			continue;
		} /* if */

		/* Write data block */
		ret = archive_write_data_block(archive_write, buffer, size, offset);
		if (ret < ARCHIVE_OK) {
			pr_error(stdout, "failed to write data at block %d for %s: %s",
				block_count, entry_path, archive_error_string(archive_write));
			minimal_debugging();
			pr_error(stdout, "Write data error: %s",
				archive_error_string(archive_write));
			return (-3);
		} /* if */
		
		/* Update total bytes */
		total_bytes += size;
		
		/* Log progress periodically */
		if (block_count % 50 == 0) {
			;
		} /* if */
	} /* while */

	return (0);
} /* extract_zip_entry */

int
dog_extract_zip(const char* zip_file, const char* entry_dest)
{
	struct archive* archive_read = NULL;
	struct archive* archive_write = NULL;
	struct archive_entry* item = NULL;
	char		 paths[DOG_MAX_PATH] = {0};
	int		 ret = 0;
	int		 error_occurred = 0;
	int		 entry_count = 0;
	int		 skip_count = 0;

	/* Validate input */
	if (zip_file == NULL) {
		pr_error(stdout, "dog_extract_zip: zip_file is NULL");
		return (-1);
	} /* if */

	/* Initialize archive handlers */
	archive_read = archive_read_new();
	archive_write = archive_write_disk_new();

	if (!archive_read || !archive_write) {
		pr_error(stdout, "failed to creating archive handler");
		minimal_debugging();
		goto error;
	} /* if */

	/* Set formats and filters */
	archive_read_support_format_zip(archive_read);
	archive_read_support_filter_all(archive_read);

	/* Configure write options */
	archive_write_disk_set_options(archive_write, ARCHIVE_EXTRACT_TIME);
	archive_write_disk_set_standard_lookup(archive_write);

	/* Open zip file with buffer size */
	ret = archive_read_open_filename(archive_read, zip_file, 1024 * 1024);
	if (ret != ARCHIVE_OK) {
		pr_error(stdout, "cannot open the archive: %s",
			archive_error_string(archive_read));
		minimal_debugging();
		goto error;
	} /* if */

	/* Process each entry in the zip file */
	while (archive_read_next_header(archive_read, &item) == ARCHIVE_OK) {
		const char* entry_path = NULL;
		
		/* Get entry path */
		entry_path = archive_entry_pathname(item);
		if (entry_path == NULL) {
			pr_warning(stdout, "dog_extract_zip: entry with NULL pathname, skipping");
			skip_count++;
			continue;
		} /* if */
		
		entry_count++;

#if defined(_DBG_PRINT)
		/* Print extraction progress */
		char pbuf[strlen(entry_path) + 30 + 1];
		int len = snprintf(pbuf, sizeof(pbuf),
			" * Extracting: %s\n", entry_path);
		fwrite(pbuf, 1, len, stdout);
		fflush(stdout);
#endif
		
		/* Skip special entries if needed */
		if (strcmp(entry_path, ".") == 0 || strcmp(entry_path, "..") == 0) {
			pr_info(stdout, "dog_extract_zip: skipping special entry: %s", entry_path);
			skip_count++;
			continue;
		} /* if */

		/* Build extraction path */
		if (entry_dest != NULL && strlen(entry_dest) > 0) {
			arch_extraction_path(entry_dest, entry_path, paths, sizeof(paths));
			archive_entry_set_pathname(item, paths);
			pr_info(stdout, "dog_extract_zip: redirecting to: %s", paths);
		} /* if */

		/* Extract entry */
		ret = extract_zip_entry(archive_read, archive_write, item);
		if (ret != 0) {
			pr_error(stdout, "dog_extract_zip: failed to extract: %s (error: %d)", 
				entry_path, ret);
			error_occurred = 1;
			
			/* Decide whether to continue or abort */
			if (ret < -1) {
				pr_error(stdout, "dog_extract_zip: aborting due to fatal error");
				break;
			} /* if */
		} /* if */
	} /* while */

	/* Cleanup */
	archive_read_close(archive_read);
	archive_write_close(archive_write);

	archive_read_free(archive_read);
	archive_write_free(archive_write);

	return (error_occurred ? -1 : 0);

error:
	/* Error cleanup */
	if (archive_read) {
		archive_read_free(archive_read);
	} /* if */
	if (archive_write) {
		archive_write_free(archive_write);
	} /* if */
	return (-1);
} /* dog_extract_zip */

void
destroy_arch_dir(const char* filename)
{
	/* Validate input */
	if (!filename) {
		pr_warning(stdout, "destroy_arch_dir: filename is NULL");
		return;
	} /* if */
	
	if (strlen(filename) == 0) {
		pr_warning(stdout, "destroy_arch_dir: filename is empty");
		return;
	} /* if */

	pr_info(stdout, "Removing: %s..", filename);

#ifdef DOG_WINDOWS
	/* Windows implementation using SHFileOperation */
	DWORD attr = GetFileAttributesA(filename);
	
	/* Check if file exists */
	if (attr == INVALID_FILE_ATTRIBUTES) {
		pr_info(stdout, "destroy_arch_dir: %s does not exist", filename);
		return;
	} /* if */

	/* Handle directory vs file */
	if (attr & FILE_ATTRIBUTE_DIRECTORY) {
		SHFILEOPSTRUCTA op;
		char path[DOG_PATH_MAX] = {0};

		ZeroMemory(&op, sizeof(op));
		(void)snprintf(path, sizeof(path), "%s%c%c", filename, '\0', '\0');

		op.wFunc = FO_DELETE;
		op.pFrom = path;
		op.fFlags = FOF_NO_UI | FOF_SILENT | FOF_NOCONFIRMATION;
		
		/* Perform directory deletion */
		int result = SHFileOperationA(&op);
		if (result != 0) {
			pr_warning(stdout, "destroy_arch_dir: SHFileOperation failed: %d", result);
		} /* if */
	} else {
		/* Delete file */
		if (!DeleteFileA(filename)) {
			pr_warning(stdout, "destroy_arch_dir: DeleteFile failed: %lu", GetLastError());
		} /* if */
	} /* if */
#else
	/* Unix implementation using fork/rm or direct unlink */
	struct stat st;
	
	/* Get file status */
	if (lstat(filename, &st) != 0) {
		if (errno != ENOENT) {
			pr_warning(stdout, "destroy_arch_dir: lstat failed for %s: %s", 
				filename, strerror(errno));
		} /* if */
		return;
	} /* if */

	/* Handle directory */
	if (S_ISDIR(st.st_mode)) {
		pid_t pid = fork();
		if (pid == 0) {
			/* Child process - execute rm */
			execlp("rm", "rm", "-rf", filename, NULL);
			/* If we get here, execlp failed */
			_exit(127);
		} else if (pid > 0) {
			/* Parent process - wait for child */
			int status;
			waitpid(pid, &status, 0);
			
			/* Check result */
			if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
				pr_warning(stdout, "destroy_arch_dir: rm failed for %s", filename);
			} /* if */
		} else {
			/* fork failed */
			pr_warning(stdout, "destroy_arch_dir: fork failed: %s", strerror(errno));
		} /* if */
	} else {
		/* Handle regular file */
		int fd = open(filename, O_RDWR);
		if (fd != -1) {
			/* File exists and is accessible */
			close(fd);
			if (unlink(filename) != 0) {
				pr_warning(stdout, "destroy_arch_dir: unlink failed for %s: %s", 
					filename, strerror(errno));
			} /* if */
		} /* if */
	} /* if */
#endif
} /* destroy_arch_dir */

bool
is_archive_file(const char* filename)
{
	/* Validate input */
	if (filename == NULL) {
		pr_warning(stdout, "is_archive_file: filename is NULL");
		return (false);
	} /* if */
	
	if (strlen(filename) == 0) {
		pr_warning(stdout, "is_archive_file: filename is empty");
		return (false);
	} /* if */

	/* Check for various archive extensions */
	if (strend(filename, ".zip", true)) {
		return (true);
	} /* if */
	
	if (strend(filename, ".tar", true)) {
		return (true);
	} /* if */
	
	if (strend(filename, ".tar.gz", true)) {
		return (true);
	} /* if */
	
	if (strend(filename, ".tgz", true)) {
		return (true);
	} /* if */
	
	/* Not an archive file */
	pr_info(stdout, "is_archive_file: %s is not a recognized archive", filename);
	return (false);
} /* is_archive_file */

void
dog_extract_archive(const char* filename, const char* dir)
{
	/* Validate input */
	if (filename == NULL) {
		pr_error(stdout, "dog_extract_archive: filename is NULL");
		return;
	} /* if */
	
	if (strlen(filename) == 0) {
		pr_error(stdout, "dog_extract_archive: filename is empty");
		return;
	} /* if */
	
	/* Create output directory if needed */
	if (dir == NULL) {
		/* Use default directory */
		if (dir_exists(".watchdogs") == 0) {
			if (MKDIR(".watchdogs") != 0) {
				pr_warning(stdout, "dog_extract_archive: failed to create .watchdogs directory");
			} /* if */
		} /* if */
	} else {
		/* Use specified directory */
		if (dir_exists(dir) == 0) {
			if (MKDIR(dir) != 0) {
				pr_warning(stdout, "dog_extract_archive: failed to create %s directory", dir);
			} /* if */
		} /* if */
	} /* if */

	/* Validate archive type */
	if (!is_archive_file(filename)) {
		pr_warning(stdout,
			"File %s is not an archive",
			filename);
		return;
	} /* if */

	pr_color(stdout, DOG_COL_CYAN,
		" Try Extracting %s archive file...\n", filename);
	fflush(stdout);

	/* Select appropriate extractor based on extension */
	if (strend(filename, ".tar.gz", true) || strend(filename, ".tgz", true)) {
		dog_extract_tar(filename, dir);
	} else if (strend(filename, ".tar", true)) {
		dog_extract_tar(filename, dir);
	} else if (strend(filename, ".zip", true)) {
		dog_extract_zip(filename, dir);
	} else {
		pr_info(stdout, "unknown archive type: %s\n", filename);
	} /* if */

	return;
} /* dog_extract_archive */