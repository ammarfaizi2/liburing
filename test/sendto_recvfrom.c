/* SPDX-License-Identifier: MIT */
/*
 * Simple test case showing using sendto and recvfrom through io_uring
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <pthread.h>

#include "liburing.h"
#include "helpers.h"

static char str[] = "This is a test of sendto and recvfrom over io_uring!";

#define MAX_MSG	128

#define PORT2	10201
#define PORT	10200
#define HOST	"127.0.0.1"

struct recvfrom_data {
	pthread_mutex_t mutex;
	int use_sqthread;
	int registerfiles;
	int explicit_dst_src;
	struct sockaddr_in recvfrom_src;
};

static int recvfrom_prep(struct io_uring *ring, struct iovec *iov, int *sock,
			 struct recvfrom_data *rd)
{
	struct sockaddr_in saddr;
	struct sockaddr *saddr_p;
	socklen_t *saddr_len_p;
	socklen_t saddr_len;
	struct io_uring_sqe *sqe;
	int sockfd, ret, val, use_fd;

	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = htonl(INADDR_ANY);
	saddr.sin_port = htons(PORT);

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		perror("socket");
		return 1;
	}

	val = 1;
	setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));

	ret = bind(sockfd, (struct sockaddr *)&saddr, sizeof(saddr));
	if (ret < 0) {
		perror("bind");
		goto err;
	}

	if (rd->explicit_dst_src) {
		memset(&rd->recvfrom_src, 0, sizeof(rd->recvfrom_src));
		saddr_len = sizeof(rd->recvfrom_src);
		saddr_p = (struct sockaddr *) &rd->recvfrom_src;
		saddr_len_p = &saddr_len;
	} else {
		saddr_p = NULL;
		saddr_len_p = NULL;
	}

	if (rd->registerfiles) {
		ret = io_uring_register_files(ring, &sockfd, 1);
		if (ret) {
			fprintf(stderr, "file reg failed\n");
			goto err;
		}
		use_fd = 0;
	} else {
		use_fd = sockfd;
	}

	sqe = io_uring_get_sqe(ring);
	io_uring_prep_recvfrom(sqe, use_fd, iov->iov_base, iov->iov_len, 0,
			       saddr_p, saddr_len_p);

	if (rd->registerfiles)
		sqe->flags |= IOSQE_FIXED_FILE;
	sqe->user_data = 2;

	ret = io_uring_submit(ring);
	if (ret <= 0) {
		fprintf(stderr, "submit failed: %d\n", ret);
		goto err;
	}

	*sock = sockfd;
	return 0;
err:
	close(sockfd);
	return 1;
}

static int do_recv(struct io_uring *ring, struct iovec *iov,
		   struct recvfrom_data *rd)
{
	struct io_uring_cqe *cqe;
	int ret;

	ret = io_uring_wait_cqe(ring, &cqe);
	if (ret) {
		fprintf(stdout, "wait_cqe: %d\n", ret);
		goto err;
	}
	if (cqe->res == -EINVAL) {
		fprintf(stdout, "recvfrom not supported, skipping\n");
		return 0;
	}
	if (cqe->res < 0) {
		fprintf(stderr, "failed cqe: %d\n", cqe->res);
		goto err;
	}

	if (cqe->res -1 != strlen(str)) {
		fprintf(stderr, "got wrong length: %d/%d\n", cqe->res,
							(int) strlen(str) + 1);
		goto err;
	}

	if (strcmp(str, iov->iov_base)) {
		fprintf(stderr, "string mismatch\n");
		goto err;
	}

	if (rd->explicit_dst_src) {
		if (rd->recvfrom_src.sin_family != AF_INET) {
			fprintf(stderr, "wrong saddr2.sin_family\n");
			goto err;
		}

		if (rd->recvfrom_src.sin_addr.s_addr != inet_addr(HOST)) {
			fprintf(stderr, "wrong saddr2.s_addr\n");
			goto err;
		}

		if (rd->recvfrom_src.sin_port != htons(PORT2)) {
			fprintf(stderr, "wrong saddr2.sin_port\n");
			goto err;
		}
	}

	return 0;
err:
	return 1;
}

static void *recvfrom_fn(void *data)
{
	struct recvfrom_data *rd = data;
	char buf[MAX_MSG + 1];
	struct iovec iov = {
		.iov_base = buf,
		.iov_len = sizeof(buf) - 1,
	};
	struct io_uring_params p = { };
	struct io_uring ring;
	int ret, sock;

	if (rd->use_sqthread)
		p.flags = IORING_SETUP_SQPOLL;
	ret = t_create_ring_params(1, &ring, &p);
	if (ret == T_SETUP_SKIP) {
		pthread_mutex_unlock(&rd->mutex);
		ret = 0;
		goto err;
	} else if (ret < 0) {
		pthread_mutex_unlock(&rd->mutex);
		goto err;
	}

	if (rd->use_sqthread && !rd->registerfiles) {
		if (!(p.features & IORING_FEAT_SQPOLL_NONFIXED)) {
			fprintf(stdout, "Non-registered SQPOLL not available, skipping\n");
			pthread_mutex_unlock(&rd->mutex);
			goto err;
		}
	}

	ret = recvfrom_prep(&ring, &iov, &sock, rd);
	if (ret) {
		fprintf(stderr, "recvfrom_prep failed: %d\n", ret);
		goto err;
	}
	pthread_mutex_unlock(&rd->mutex);
	ret = do_recv(&ring, &iov, rd);

	close(sock);
	io_uring_queue_exit(&ring);
err:
	return (void *)(intptr_t)ret;
}

static int bind_socket_for_sendto(int sockfd)
{
	struct sockaddr_in saddr;
	int ret, val;

	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = inet_addr(HOST);
	saddr.sin_port = htons(PORT2);

	val = 1;
	setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));

	ret = bind(sockfd, (struct sockaddr *)&saddr, sizeof(saddr));
	if (ret < 0) {
		perror("bind in bind_socket_for_sendto");
		return 1;
	}


	return 0;
}

static int do_sendto(struct recvfrom_data *rd)
{
	struct sockaddr_in saddr;
	struct iovec iov = {
		.iov_base = str,
		.iov_len = sizeof(str),
	};
	struct io_uring ring;
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	struct sockaddr *saddr_p;
	socklen_t saddr_len;
	int sockfd, ret;

	ret = io_uring_queue_init(1, &ring, 0);
	if (ret) {
		fprintf(stderr, "queue init failed: %d\n", ret);
		return 1;
	}

	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(PORT);
	inet_pton(AF_INET, HOST, &saddr.sin_addr);

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		perror("socket");
		return 1;
	}

	if (rd->explicit_dst_src) {
		saddr_p = (struct sockaddr *)&saddr;
		saddr_len = sizeof(saddr);

		/*
		 * We need to bind() here because the recvfrom() side
		 * will use an explicit source (addr and port).
		 */
		bind_socket_for_sendto(sockfd);
	} else {
		saddr_p = NULL;
		saddr_len = 0;
		/*
		 * Only connect() when sendto() is done without explicit
		 * destination (addr and port).
		 */
		ret = connect(sockfd, (struct sockaddr *)&saddr, sizeof(saddr));
		if (ret < 0) {
			perror("connect");
			return 1;
		}
	}

	sqe = io_uring_get_sqe(&ring);
	io_uring_prep_sendto(sqe, sockfd, iov.iov_base, iov.iov_len, 0,
			     saddr_p, saddr_len);
	sqe->user_data = 1;

	ret = io_uring_submit(&ring);
	if (ret <= 0) {
		fprintf(stderr, "submit failed: %d\n", ret);
		goto err;
	}

	ret = io_uring_wait_cqe(&ring, &cqe);
	if (cqe->res == -EINVAL) {
		fprintf(stdout, "sendto not supported, skipping\n");
		close(sockfd);
		return 0;
	}
	if (cqe->res != iov.iov_len) {
		fprintf(stderr, "failed cqe: %d\n", cqe->res);
		goto err;
	}

	close(sockfd);
	return 0;
err:
	close(sockfd);
	return 1;
}

static int test(int use_sqthread, int regfiles, int explicit_dst_src)
{
	pthread_mutexattr_t attr;
	pthread_t recvfrom_thread;
	struct recvfrom_data rd;
	int ret;
	void *retval;

	pthread_mutexattr_init(&attr);
	pthread_mutexattr_setpshared(&attr, 1);
	pthread_mutex_init(&rd.mutex, &attr);
	pthread_mutex_lock(&rd.mutex);
	rd.use_sqthread = use_sqthread;
	rd.registerfiles = regfiles;
	rd.explicit_dst_src = explicit_dst_src;

	ret = pthread_create(&recvfrom_thread, NULL, recvfrom_fn, &rd);
	if (ret) {
		fprintf(stderr, "Thread create failed: %d\n", ret);
		pthread_mutex_unlock(&rd.mutex);
		return 1;
	}

	pthread_mutex_lock(&rd.mutex);
	do_sendto(&rd);
	pthread_join(recvfrom_thread, &retval);
	return (int)(intptr_t)retval;
}

int main(int argc, char *argv[])
{
	int ret;

	if (argc > 1)
		return 0;

	ret = test(0, 0, 0);
	if (ret) {
		fprintf(stderr, "test sqthread=0 failed\n");
		return ret;
	}

	ret = test(1, 1, 0);
	if (ret) {
		fprintf(stderr, "test sqthread=1 reg=1 failed\n");
		return ret;
	}

	ret = test(1, 0, 0);
	if (ret) {
		fprintf(stderr, "test sqthread=1 reg=0 failed\n");
		return ret;
	}

	ret = test(0, 0, 1);
	if (ret) {
		fprintf(stderr, "test sqthread=0 explicit_dst_src=1 failed\n");
		return ret;
	}

	ret = test(1, 1, 1);
	if (ret) {
		fprintf(stderr, "test sqthread=1 reg=1 explicit_dst_src=1 failed\n");
		return ret;
	}

	ret = test(1, 0, 1);
	if (ret) {
		fprintf(stderr, "test sqthread=1 reg=0 explicit_dst_src=1 failed\n");
		return ret;
	}

	return 0;
}
