#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/uio.h>

#define FILE "/dev/dmautest"

#define BUF_SIZE 4096

static void usage(void)
{
        printf("<app_name> [options]\n"
        "-p           ; pre-fault the buffer\n"
        "-s           ; use iovec for I/O\n"
        "-l <length>  ; total test buffer size\n"
	"-v           ' verify result\n"
	"-h           ; print this message\n");
}

#define MAX_U_IOVECS  16

#define IOVEC_SIZE  0x10000

int main (int argc, char *argv[])
{
	int fd, err;
	char *buf;
	unsigned long buf_size = BUF_SIZE;
	int flags = 0;
	int pre_fault = 0;
	int sg = 0;
	int verify = 0;
	int opt, i;
        struct iovec iov[MAX_U_IOVECS];
	ssize_t iov_len;

        while ((opt = getopt(argc, argv, "l:vsph")) != -1) {
		switch(opt) {
			case 'l':
				buf_size = strtoul(optarg, NULL, 0);
				break;
			case 'p':
				pre_fault = 1;
				break;
			case 's':
				sg = 1;
				break;
			case 'v':
				verify = 1;
				break;
			case 'h':
				usage();
				exit(0);
			default:
				break;
		}
	}

        fd = open(FILE, O_RDWR);
        if (fd < 0) {
                int err = -errno;
                printf("open error %d\n", err);
                return err;
        }

	buf = malloc(buf_size);

	if (!buf) {
		printf("buffer allocation failed\n");
		exit(-1);
	}

	if(pre_fault)
		memset(buf, 0, buf_size);

	if (sg) {
		int iovec_count = ((buf_size - 1)/ IOVEC_SIZE) + 1;
		ssize_t iovec_size;
		ssize_t total_len;

		if (iovec_count > MAX_U_IOVECS)
			iovec_count = MAX_U_IOVECS;

		iovec_size = buf_size / iovec_count;

		total_len = 0;
		for (i = 0; i < iovec_count; i++) {
			iov[i].iov_base = buf + total_len;

			iov_len = (buf_size - total_len) >= iovec_size? iovec_size: buf_size - total_len;

			iov[i].iov_len = iov_len;

			total_len += iov_len;
			printf("[%d] iov base %p iov_len %ld total_len %ld\n", i, iov[i].iov_base, iov[i].iov_len, total_len);
		}

		if ((err = readv(fd, iov, iovec_count)) == buf_size)
			printf("Copy sg to user success\n");
		else
			printf("Copy sg to user failed %d\n", err);
	} else {

		if ((err = read(fd, buf, buf_size)) == buf_size)
			printf("Copy to user success\n");
		else
			printf("Copy to user failed %d\n", err);
	}

	if (verify) {
		ssize_t remaining = buf_size, len;
		char expected[4096];
		char *buf1 = buf;

		memset(expected, 0xb, 4096);
		while (remaining > 0) {
			len = remaining > 4096? 4096: remaining;

			if (memcmp(expected, buf1, len)) {
				printf("buffer validation failed.\n");
				break;
			}
			remaining -= len;
			buf1 += len;
		}
		if (remaining) {
			int i;
			for (i = 0; i < 4096; i++) {
				if (buf1[i] != expected[i]) {
					printf("mismatch happened at offset %ld %d %d\n", buf_size - remaining + i, expected[i], buf1[i]);
					break;
				}
			}
		}
	}

	free(buf);
	return 0;
}

