// SPDX-License-Identifier: MIT
/*
 * Copyright (C) 2022 Ammar Faizi <ammarfaizi2@gnuweeb.org>
 *
 * A test program to answer Jens' email.
 *
 * sendmsg()/recvmsg() vs sendto()/recvfrom()
 *
 * Link: https://lore.kernel.org/io-uring/98d4f268-5945-69a7-cec7-bccfcdedde1c@kernel.dk/
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <liburing.h>

#define NR_CLIENT_LOOP		1000
#define NR_CLIENT_ENTRIES	8192
#define BUFSIZE			1300
#define SERVER_BIND_ADDR	"0.0.0.0"
#define SERVER_BIND_PORT	12345
#define MAGIC_BYTE_STOP		((char) 0xaa)
#define noinline		__attribute__((__noinline__))
#define __cold			__attribute__((__cold__))
#define __hot			__attribute__((__hot__))

struct app_ctx {
	struct io_uring		server_ring;
	struct io_uring		client_ring;
	pthread_t		server_thread;
	int			server_fd;
	int			client_fd;
};

__cold static int create_ring(unsigned entries, struct io_uring *ring)
{
	int ret;

	ret = io_uring_queue_init(entries, ring, 0);
	if (ret < 0) {
		fprintf(stderr, "io_uring_queue_init(): %s\n", strerror(-ret));
		return ret;
	}
	return ret;
}

__cold static void destroy_ring(struct io_uring *ring)
{
	io_uring_queue_exit(ring);
}

__cold noinline static int create_server_socket(void)
{
	struct sockaddr_in saddr;
	int sock_fd;
	int ret;
	int tmp;

	sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock_fd < 0) {
		ret = -errno;
		perror("socket");
		return ret;
	}

	tmp = 1;
	ret = setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &tmp, sizeof(tmp));
	if (ret < 0) {
		ret = -errno;
		perror("setsockopt");
		goto out_close;
	}

	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = inet_addr(SERVER_BIND_ADDR);
	saddr.sin_port = htons(SERVER_BIND_PORT);

	ret = bind(sock_fd, (struct sockaddr *) &saddr, sizeof(saddr));
	if (ret < 0) {
		ret = -errno;
		perror("bind");
		goto out_close;
	}

	return sock_fd;

out_close:
	close(sock_fd);
	return ret;
}

static int create_client_socket(void)
{
	int sock_fd;
	int ret;

	sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock_fd < 0) {
		ret = -errno;
		perror("socket");
		return ret;
	}
	return sock_fd;
}

static void *mmap_buffer(size_t len)
{
	int err;
	void *buf;

	buf = mmap(NULL, len, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE,
		   -1, 0);
	if (buf == MAP_FAILED) {
		err = errno;
		perror("mmap");
		errno = err;
		return NULL;
	}

	err = mlock(buf, BUFSIZE);
	if (err < 0) {
		perror("mlock");
		fprintf(stderr, "Ignoring mlock error...\n");
	}
	return buf;
}

static void *sendto_recvfrom_server_worker(void *ctx_p)
{
	struct sockaddr_in src_addr;
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	socklen_t src_addr_len;
	struct io_uring *ring;
	struct app_ctx *ctx;
	unsigned total_recv;
	unsigned head;
	char *buf;
	int tmp;
	int ret;
	int fd;

	ret = -ENOMEM;
	buf = mmap_buffer(BUFSIZE);
	if (!buf)
		goto out;

	ret = 0;
	ctx = ctx_p;
	fd = ctx->server_fd;
	ring = &ctx->server_ring;
	total_recv = 0;

	while (true) {
		sqe = io_uring_get_sqe(ring);
		if (!sqe) {
			/* Should not be possible. */
			ret = -EAGAIN;
			break;
		}

		src_addr_len = sizeof(src_addr);
		io_uring_prep_recvfrom(sqe, fd, buf, BUFSIZE, 0,
				       (struct sockaddr *) &src_addr,
				       &src_addr_len);

		tmp = io_uring_submit_and_wait(ring, 1);
		if (tmp <= 0) {
			fprintf(stderr, "Server submit failed: %d\n", tmp);
			ret = tmp;
			break;
		}

		io_uring_for_each_cqe(ring, head, cqe) {
			total_recv++;
			ret = cqe->res;
			if (ret < 0) {
				fprintf(stderr, "recvfrom error: %s\n",
					strerror(-ret));
				goto out_unmap;
			}
			if (buf[0] == MAGIC_BYTE_STOP) {
				io_uring_cqe_seen(ring, cqe);
				goto out_unmap;
			}
			io_uring_cqe_seen(ring, cqe);
		}
	}

out_unmap:
	munmap(buf, BUFSIZE);
out:
	return (void *) (intptr_t) ret;
}

static void *sendto_recvfrom_client_worker(void *ctx_p)
{
	struct sockaddr_in dst_addr;
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	struct io_uring *ring;
	char (*buf)[BUFSIZE];
	struct app_ctx *ctx;
	unsigned total_send;
	unsigned head;
	size_t loop;
	size_t i;
	int tmp;
	int ret;
	int fd;

	ret = -ENOMEM;
	buf = mmap_buffer(NR_CLIENT_ENTRIES * BUFSIZE);
	if (!buf)
		goto out;

	ret = 0;
	ctx = ctx_p;
	fd = ctx->client_fd;
	ring = &ctx->client_ring;

	memset(&dst_addr, 0, sizeof(dst_addr));
	dst_addr.sin_family = AF_INET;
	dst_addr.sin_addr.s_addr = inet_addr(SERVER_BIND_ADDR);
	dst_addr.sin_port = htons(SERVER_BIND_PORT);
	memset(buf, 0xff, NR_CLIENT_ENTRIES * BUFSIZE);

	loop = 0;
do_burst:
	for (i = 0; i < NR_CLIENT_ENTRIES; i++) {
		sqe = io_uring_get_sqe(ring);
		if (!sqe)
			break;
		io_uring_prep_sendto(sqe, fd, buf[i], BUFSIZE, 0,
				     (struct sockaddr *) &dst_addr,
				     sizeof(dst_addr));
	}

	tmp = io_uring_submit_and_wait(ring, NR_CLIENT_ENTRIES);
	if (tmp <= 0) {
		fprintf(stderr, "Client submit failed: %d\n", tmp);
		ret = tmp;
		goto out_unmap;
	}

	total_send = 0;
	io_uring_for_each_cqe(ring, head, cqe) {
		total_send++;
		ret = cqe->res;
		if (ret < 0) {
			fprintf(stderr,
				"sendto error: %s\n", strerror(-ret));
			goto out_unmap;
		}
	}
	io_uring_cq_advance(ring, total_send);

	if (loop++ < NR_CLIENT_LOOP)
		goto do_burst;


	printf("Client finished!\n");
	printf("Stopping...\n");
	buf[0][0] = MAGIC_BYTE_STOP;
	ret = sendto(fd, buf[0], 1, 0, &dst_addr, sizeof(dst_addr));
	if (ret < 0) {
		ret = -errno;
		perror("sendto");
	} else {
		ret = 0;
	}

out_unmap:
	munmap(buf, BUFSIZE);
out:
	return (void *) (intptr_t) ret;
}

static void *sendmsg_recvmsg_server_worker(void *ctx_p)
{
	struct sockaddr_in src_addr;
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	struct io_uring *ring;
	struct app_ctx *ctx;
	unsigned total_recv;
	struct msghdr msg;
	struct iovec iov;
	unsigned head;
	char *buf;
	int tmp;
	int ret;
	int fd;

	ret = -ENOMEM;
	buf = mmap_buffer(BUFSIZE);
	if (!buf)
		goto out;

	ret = 0;
	ctx = ctx_p;
	fd = ctx->server_fd;
	ring = &ctx->server_ring;
	total_recv = 0;
	memset(&msg, 0, sizeof(msg));

	while (true) {
		sqe = io_uring_get_sqe(ring);
		if (!sqe) {
			/* Should not be possible. */
			ret = -EAGAIN;
			break;
		}

		msg.msg_name = &src_addr;
		msg.msg_namelen = sizeof(src_addr);
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		iov.iov_base = buf;
		iov.iov_len = BUFSIZE;
		io_uring_prep_recvmsg(sqe, fd, &msg, 0);

		tmp = io_uring_submit_and_wait(ring, 1);
		if (tmp <= 0) {
			fprintf(stderr, "Server submit failed: %d\n", tmp);
			ret = tmp;
			break;
		}

		io_uring_for_each_cqe(ring, head, cqe) {
			total_recv++;
			ret = cqe->res;
			if (ret < 0) {
				fprintf(stderr, "recvfrom error: %s\n",
					strerror(-ret));
				goto out_unmap;
			}
			if (buf[0] == MAGIC_BYTE_STOP) {
				io_uring_cqe_seen(ring, cqe);
				goto out_unmap;
			}
			io_uring_cqe_seen(ring, cqe);
		}
	}

out_unmap:
	munmap(buf, BUFSIZE);
out:
	return (void *) (intptr_t) ret;
}

static void *sendmsg_recvmsg_client_worker(void *ctx_p)
{
	struct sendto_ctx {
		char buf[BUFSIZE];
		struct msghdr msg;
		struct iovec iov;
	};

	struct sockaddr_in dst_addr;
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	struct sendto_ctx *sctx;
	struct io_uring *ring;
	struct app_ctx *ctx;
	unsigned total_send;
	unsigned head;
	size_t loop;
	size_t i;
	int tmp;
	int ret;
	int fd;

	ret = -ENOMEM;
	sctx = mmap_buffer(NR_CLIENT_ENTRIES * sizeof(*sctx));
	if (!sctx)
		goto out;

	ret = 0;
	ctx = ctx_p;
	fd = ctx->client_fd;
	ring = &ctx->client_ring;

	memset(&dst_addr, 0, sizeof(dst_addr));
	dst_addr.sin_family = AF_INET;
	dst_addr.sin_addr.s_addr = inet_addr(SERVER_BIND_ADDR);
	dst_addr.sin_port = htons(SERVER_BIND_PORT);

	for (i = 0; i < NR_CLIENT_ENTRIES; i++) {
		memset(&sctx[i].msg, 0, sizeof(sctx[i].msg));
		memset(sctx[i].buf, 0xff, sizeof(sctx[i].buf));
		sctx[i].msg.msg_name = &dst_addr;
		sctx[i].msg.msg_namelen = sizeof(dst_addr);
		sctx[i].msg.msg_iov = &sctx[i].iov;
		sctx[i].msg.msg_iovlen = 1;
		sctx[i].iov.iov_base = sctx[i].buf;
		sctx[i].iov.iov_len = sizeof(sctx[i].buf);
	}

	loop = 0;
do_burst:
	for (i = 0; i < NR_CLIENT_ENTRIES; i++) {
		sqe = io_uring_get_sqe(ring);
		if (!sqe)
			break;
		io_uring_prep_sendmsg(sqe, fd, &sctx[i].msg, 0);
	}

	tmp = io_uring_submit_and_wait(ring, NR_CLIENT_ENTRIES);
	if (tmp <= 0) {
		fprintf(stderr, "Client submit failed: %d\n", tmp);
		ret = tmp;
		goto out_unmap;
	}

	total_send = 0;
	io_uring_for_each_cqe(ring, head, cqe) {
		total_send++;
		ret = cqe->res;
		if (ret < 0) {
			fprintf(stderr,
				"sendto error: %s\n", strerror(-ret));
			goto out_unmap;
		}
	}
	io_uring_cq_advance(ring, total_send);

	if (loop++ < NR_CLIENT_LOOP)
		goto do_burst;


	printf("Client finished!\n");
	printf("Stopping...\n");
	sctx[0].buf[0] = MAGIC_BYTE_STOP;
	ret = sendto(fd, sctx[0].buf, 1, 0, &dst_addr, sizeof(dst_addr));
	if (ret < 0) {
		ret = -errno;
		perror("sendto");
	} else {
		ret = 0;
	}

out_unmap:
	munmap(sctx, NR_CLIENT_ENTRIES * sizeof(*sctx));
out:
	return (void *) (intptr_t) ret;
}


__cold static int spawn_worker(struct app_ctx *ctx, void *(*func)(void *))
{
	int ret;

	ret = pthread_create(&ctx->server_thread, NULL, func, ctx);
	if (ret) {
		ret = errno;
		perror("pthread_create");
		return ret;
	}
	return 0;
}

static void show_usage(const char *app)
{
	puts("Usage:");
	printf("\t%s sendmsg_recvmsg\n", app);
	printf("\t%s sendto_recvfrom\n", app);
}

static int run_test(const char *app, const char *arg)
{
	enum {
		TEST_SENDMSG_RECVMSG,
		TEST_SENDTO_RECVFROM
	};

	void *server_ret = NULL;
	struct app_ctx ctx;
	int target_test;
	int ret;
	int tmp;

	if (!strcmp(arg, "sendmsg_recvmsg")) {
		target_test = TEST_SENDMSG_RECVMSG;
	} else if (!strcmp(arg, "sendto_recvfrom")) {
		target_test = TEST_SENDTO_RECVFROM;
	} else {
		fprintf(stderr, "Invalid target_test\n");
		show_usage(app);
		return -EINVAL;
	}

	memset(&ctx, 0, sizeof(ctx));
	ret = create_server_socket();
	if (ret < 0)
		return ret;
	ctx.server_fd = ret;

	ret = create_ring(1, &ctx.server_ring);
	if (ret < 0)
		goto out_server_sock;

	ret = create_client_socket();
	if (ret < 0)
		goto out_server_ring;
	ctx.client_fd = ret;

	ret = create_ring(NR_CLIENT_ENTRIES, &ctx.client_ring);
	if (ret < 0)
		goto out_client_sock;


	switch (target_test) {
	case TEST_SENDTO_RECVFROM:
		ret = spawn_worker(&ctx, sendto_recvfrom_server_worker);
		if (ret < 0)
			goto out_client_ring;

		ret = (int) (intptr_t) sendto_recvfrom_client_worker(&ctx);
		tmp = pthread_join(ctx.server_thread, &server_ret);
		if (tmp < 0) {
			ret = tmp;
			goto out_client_ring;
		}
		break;

	case TEST_SENDMSG_RECVMSG:
		ret = spawn_worker(&ctx, sendmsg_recvmsg_server_worker);
		if (ret < 0)
			goto out_client_ring;

		ret = (int) (intptr_t) sendmsg_recvmsg_client_worker(&ctx);
		tmp = pthread_join(ctx.server_thread, &server_ret);
		if (tmp < 0) {
			ret = tmp;
			goto out_client_ring;
		}
		break;
	}

	if (server_ret)
		ret = (int) (intptr_t) server_ret;

out_client_ring:
	destroy_ring(&ctx.client_ring);
out_client_sock:
	close(ctx.client_fd);
out_server_ring:
	destroy_ring(&ctx.server_ring);
out_server_sock:
	close(ctx.server_fd);
	return ret;
}

int main(int argc, char **argv)
{
	if (argc != 2) {
		show_usage(argv[0]);
		return 0;
	}

	return -run_test(argv[0], argv[1]);
}
