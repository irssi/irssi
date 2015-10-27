/*
 sandbox.c : irssi

    Copyright (C) 2015 Namsun Ch'o

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include <errno.h>
#include <linux/futex.h>
#include <linux/in.h>
#include <linux/prctl.h>
#include <seccomp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/capability.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/termios.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "sandbox.h"

#define IRSSI_NEEDS_RDTSC
#define IRSSI_NEEDS_CAPS

/*
 * TODO:
 *	- implement user, pid, network, and mount namespaces
 *	- ensure that hardcoded file descriptors work
 *	- create automated test suite for seccomp (and/or static analysis?)
 *	- keep private keys in a separate process, (e.g https://github.com/AGWA/titus)?
 *	- add support tame() on OpenBSD, and Capsicum on FreeBSD
*/

void create_namespaces(void)
{
	/* TODO */
}

void drop_privileges(void)
{
	int tsc_state;
	size_t i;
	cap_t cap;
	cap_flag_value_t value;

	/* running as root largely defeats the purpose of using a sandbox */
	if (geteuid() == 0 || getegid() == 0) {
		fprintf(stderr, "Cannot run irssi as root when the sandbox is enabled\n");
		exit(1);
	}

	/* disable the rdtsc so it cannot be used for side-channel attacks */
#ifndef IRSSI_NEEDS_RDTSC
	if (prctl(PR_GET_TSC, &tsc_state, 0, 0, 0) < 0) {
		fprintf(stderr, "Could not get the TSC state\n");
		exit(1);
	}

	if (tsc_state == PR_TSC_ENABLE) {
		prctl(PR_SET_TSC, PR_TSC_SIGSEGV, 0, 0, 0);
		prctl(PR_GET_TSC, &tsc_state, 0, 0, 0);

		if (tsc_state != PR_TSC_SIGSEGV) {
			fprintf(stderr, "Could not disable the TSC\n");
			exit(1);
		}
	}
#endif

	/* drop any dangerous capabilities the process is running with
	 * https://forums.grsecurity.net/viewtopic.php?f=7&t=2522 */
	/* FIXME why does cap_get_proc() fail? */
#ifndef IRSSI_NEEDS_CAPS
	cap = cap_get_proc();
	if (cap == NULL) {
		fprintf(stderr, "Could not initialize capabilities (cap_get_proc failed)\n");
		exit(1);
	}

	if (cap_clear(cap) < 0) {
		fprintf(stderr, "Could not clear capabilities (cap_clear failed)\n");
		cap_free(cap);
		exit(1);
	}

	for (i = 0; i < 64; i++) {
		cap_get_flag(cap, i, CAP_EFFECTIVE, &value);
		if (value == CAP_SET) {
			fprintf(stderr, "Cannot run irssi with caps set (cap %u)\n", (unsigned)i);
			cap_free(cap);
			exit(1);
		}
	}

	cap_free(cap);
#endif
}

void enforce_resource_limits(void)
{
	size_t i;
	struct rlimit rlim;

	struct rlimit_struct_t {
		int resource;
		int limit;
	};
	const struct rlimit_struct_t rlimit_struct[9] = {
		{ RLIMIT_AS,         268435456  }, /* 256 MiB */
		{ RLIMIT_FSIZE,      1073741824 }, /* 1 GiB */
		{ RLIMIT_LOCKS,      0          },
		{ RLIMIT_MEMLOCK,    0          },
		{ RLIMIT_MSGQUEUE,   0          },
		{ RLIMIT_NOFILE,     4096       },
		{ RLIMIT_NPROC,      70         }, /* why is this so large? */
		{ RLIMIT_SIGPENDING, 0          },
		{ RLIMIT_STACK,      32768      } /* 32 KiB */
	};
	for (i = 0; i < 9; i++) {
		rlim.rlim_cur = rlimit_struct[i].limit;
		rlim.rlim_max = rlimit_struct[i].limit;

		if (setrlimit(rlimit_struct[i].resource, &rlim) < 0 && errno != EPERM) {
			fprintf(stderr, "Could not set resource limits. Errno %d\n", errno);
			exit(1);
		}
	}
}

void enable_seccomp_sandbox(void)
{
	scmp_filter_ctx ctx;
	size_t i;
	int rc;

	/* initialize the libseccomp context */
	ctx = seccomp_init(SCMP_ACT_KILL);
	if (ctx == NULL) {
		fprintf(stderr, "Could not initialize the sandbox (seccomp_init failed)\n");
		exit(1);
	}

	/* syscalls without argument filtering */
	const int noarg_whitelist[20] = {
		SCMP_SYS(brk),
		SCMP_SYS(chdir),
		SCMP_SYS(clone),
		SCMP_SYS(close),
		SCMP_SYS(exit_group),
		SCMP_SYS(fstat),
		SCMP_SYS(getegid),
		SCMP_SYS(geteuid),
		SCMP_SYS(getgid),
		SCMP_SYS(getpid),
		SCMP_SYS(getuid),
		SCMP_SYS(lseek),
		SCMP_SYS(munmap),
		SCMP_SYS(pipe),
		SCMP_SYS(rt_sigreturn),
		SCMP_SYS(set_tid_address),
		SCMP_SYS(stat),
		SCMP_SYS(umask),
		SCMP_SYS(uname)
	};
	for (i = 0; i < 20; i++) {
		rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, noarg_whitelist[i], 0);
		if (rc < 0)
			goto fail;

		rc = seccomp_syscall_priority(ctx, noarg_whitelist[i], 100);
		if (rc < 0)
			goto fail;
	}

	/* mkdir */
	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mkdir), 1,
		SCMP_A1(SCMP_CMP_EQ, 0700)); /* src/core/settings.c:828 */
	if (rc < 0)
		goto fail;

	rc = seccomp_syscall_priority(ctx, SCMP_SYS(mkdir), 50);
	if (rc < 0)
		goto fail;

	/* setsockopt */
	struct setsockopt_struct_t {
		int sockfd;
		int level;
		int optname;
		socklen_t optlen;
	};
	const struct setsockopt_struct_t setsockopt_struct[2] = {
		{ 4, SOL_SOCKET, SO_KEEPALIVE, 4 },
		{ 4, SOL_SOCKET, SO_REUSEADDR, 4 }
	};
	for (i = 0; i < 2; i++) {
		rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setsockopt), 4,
			SCMP_A0(SCMP_CMP_EQ, setsockopt_struct[i].sockfd),
			SCMP_A1(SCMP_CMP_EQ, setsockopt_struct[i].level),
			SCMP_A2(SCMP_CMP_EQ, setsockopt_struct[i].optname),
			SCMP_A4(SCMP_CMP_EQ, setsockopt_struct[i].optlen));
		if (rc < 0)
			goto fail;
	}

	rc = seccomp_syscall_priority(ctx, SCMP_SYS(setsockopt), 50);
	if (rc < 0)
		goto fail;

	/* getsockopt */
	struct getsockopt_struct_t {
		int sockfd;
		int level;
		int optname;
	};
	const struct getsockopt_struct_t getsockopt_struct[2] = {
		{ 4, SOL_SOCKET, SO_TYPE  },
		{ 4, SOL_SOCKET, SO_ERROR }
	};
	for (i = 0; i < 2; i++) {
		rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getsockopt), 3,
			SCMP_A0(SCMP_CMP_EQ, getsockopt_struct[i].sockfd),
			SCMP_A1(SCMP_CMP_EQ, getsockopt_struct[i].level),
			SCMP_A2(SCMP_CMP_EQ, getsockopt_struct[i].optname));
		if (rc < 0)
			goto fail;
	}

	rc = seccomp_syscall_priority(ctx, SCMP_SYS(getsockopt), 50);
	if (rc < 0)
		goto fail;

	/* ioctl */
	const int ioctl_array[3] = {
		TCSETSW,
		TCGETS,
		TIOCGWINSZ
	};
	for (i = 0; i < 3; i++) {
		rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 1,
			SCMP_A1(SCMP_CMP_EQ, ioctl_array[i]));
		if (rc < 0)
			goto fail;
	}

	rc = seccomp_syscall_priority(ctx, SCMP_SYS(ioctl), 50);
	if (rc < 0)
		goto fail;

	/* kill */
	rc = seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(kill), 1,
		SCMP_A1(SCMP_CMP_EQ, SIGTSTP));
	if (rc < 0)
		goto fail;

	rc = seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(kill), 1,
		SCMP_A1(SCMP_CMP_EQ, SIGKILL));
	if (rc < 0)
		goto fail;

	rc = seccomp_syscall_priority(ctx, SCMP_SYS(kill), 50);
	if (rc < 0)
		goto fail;

	/* prctl */
	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(prctl), 4,
		SCMP_A0(SCMP_CMP_EQ, PR_SET_NAME),
		SCMP_A2(SCMP_CMP_EQ, 0),
		SCMP_A3(SCMP_CMP_EQ, 0),
		SCMP_A4(SCMP_CMP_EQ, 0));
	if (rc < 0)
		goto fail;

	rc = seccomp_syscall_priority(ctx, SCMP_SYS(prctl), 50);
	if (rc < 0)
		goto fail;

	/* fcntl */
	const int fcntl_1arg_array[3] = {
		F_GETFL,
		F_GETFD,
		F_SETLK
	};
	for (i = 0; i < 3; i++) {
		rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fcntl), 1,
			SCMP_A1(SCMP_CMP_EQ, fcntl_1arg_array[i]));
		if (rc < 0)
			goto fail;
	}

	struct fcntl_2args_struct_t {
		int cmd;
		int arg;
	};
	const struct fcntl_2args_struct_t fcntl_2args_struct[3] = {
		{ F_SETFD, FD_CLOEXEC          },
		{ F_SETFL, O_RDONLY            },
		{ F_SETFL, O_RDONLY|O_NONBLOCK }
	};
	for (i = 0; i < 3; i++) {
		rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fcntl), 2,
			SCMP_A1(SCMP_CMP_EQ, fcntl_2args_struct[i].cmd),
			SCMP_A2(SCMP_CMP_EQ, fcntl_2args_struct[i].arg));
		if (rc < 0)
			goto fail;
	}

	rc = seccomp_syscall_priority(ctx, SCMP_SYS(fcntl), 50);
	if (rc < 0)
		goto fail;

	/* mprotect */
	const int mprotect_prot_array[3] = {
		PROT_NONE,
		PROT_READ,
		PROT_READ|PROT_WRITE
	};
	for (i = 0; i < 3; i++) {
		rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mprotect), 1,
			SCMP_A2(SCMP_CMP_EQ, mprotect_prot_array[i]));
		if (rc < 0)
			goto fail;
	}

	rc = seccomp_syscall_priority(ctx, SCMP_SYS(mprotect), 60);
	if (rc < 0)
		goto fail;

	/* mmap */
	struct mmap_struct_t {
		int prot;
		int flags;
	};
	const struct mmap_struct_t mmap_anon_struct[4] = {
		{ PROT_NONE,            MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE },
		{ PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS               },
		{ PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_STACK     },
		{ PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS     }
	};
	for (i = 0; i < 4; i++) {
		rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 4,
			SCMP_A2(SCMP_CMP_EQ, mmap_anon_struct[i].prot),
			SCMP_A3(SCMP_CMP_EQ, mmap_anon_struct[i].flags),
			SCMP_A4(SCMP_CMP_EQ, 0xffffffff),
			SCMP_A5(SCMP_CMP_EQ, 0));
		if (rc < 0)
			goto fail;
	}

	const struct mmap_struct_t mmap_noanon_struct[3] = {
		{ PROT_READ,           MAP_PRIVATE               },
		{ PROT_READ,           MAP_SHARED                },
		{ PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_DENYWRITE }
	};
	for (i = 0; i < 3; i++) {
		rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 4,
			SCMP_A2(SCMP_CMP_EQ, mmap_noanon_struct[i].prot),
			SCMP_A3(SCMP_CMP_EQ, mmap_noanon_struct[i].flags),
			SCMP_A4(SCMP_CMP_NE, 0xffffffff),
			SCMP_A5(SCMP_CMP_EQ, 0));
		if (rc < 0)
			goto fail;
	}

	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 4,
		SCMP_A2(SCMP_CMP_EQ, PROT_READ|PROT_WRITE),
		SCMP_A3(SCMP_CMP_EQ, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE),
		SCMP_A4(SCMP_CMP_NE, 0xffffffff),
		SCMP_A5(SCMP_CMP_NE, 0)); /* NE 0, so can't be in the struct */
	if (rc < 0)
		goto fail;

	rc = seccomp_syscall_priority(ctx, SCMP_SYS(mmap), 60);
	if (rc < 0)
		goto fail;

	/* madvise */
	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(madvise), 2,
		SCMP_A1(SCMP_CMP_EQ, 8368128),
		SCMP_A2(SCMP_CMP_EQ, MADV_DONTNEED));
	if (rc < 0)
		goto fail;

	rc = seccomp_syscall_priority(ctx, SCMP_SYS(madvise), 50);
	if (rc < 0)
		goto fail;

	/* socket */
	struct socket_struct_t {
		int domain;
		int type;
		int proto;
	};
	const struct socket_struct_t socket_struct[2] = {
		{ PF_INET, SOCK_STREAM, IPPROTO_TCP },
		{ PF_INET, SOCK_STREAM, IPPROTO_IP  }
	};
	for (i = 0; i < 2; i++) {
		rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(socket), 3,
			SCMP_A0(SCMP_CMP_EQ, socket_struct[i].domain),
			SCMP_A1(SCMP_CMP_EQ, socket_struct[i].type),
			SCMP_A2(SCMP_CMP_EQ, socket_struct[i].proto));
		if (rc < 0)
			goto fail;
	}

	rc = seccomp_syscall_priority(ctx, SCMP_SYS(socket), 50);
	if (rc < 0)
		goto fail;

	/* connect */
	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(connect), 2,
		SCMP_A0(SCMP_CMP_GE, 4),
		SCMP_A2(SCMP_CMP_EQ, 16));
	if (rc < 0)
		goto fail;

	rc = seccomp_syscall_priority(ctx, SCMP_SYS(connect), 50);
	if (rc < 0)
		goto fail;

	/* getpeername */
	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpeername), 1,
		SCMP_A0(SCMP_CMP_GE, 4));
	if (rc < 0)
		goto fail;

	rc = seccomp_syscall_priority(ctx, SCMP_SYS(getpeername), 50);
	if (rc < 0)
		goto fail;

	/* futex */
	struct futex_struct_t {
		int op;
		int val;
	};
	const struct futex_struct_t futex_struct[5] = {
		{ FUTEX_WAIT_PRIVATE, 1          },
		{ FUTEX_WAIT_PRIVATE, 2          },
		{ FUTEX_WAKE,         2147483647 },
		{ FUTEX_WAKE_PRIVATE, 1          },
		{ FUTEX_WAKE_PRIVATE, 2147483647 }
	};
	for (i = 0; i < 5; i++) {
		rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(futex), 2,
			SCMP_A1(SCMP_CMP_EQ, futex_struct[i].op),
			SCMP_A2(SCMP_CMP_EQ, futex_struct[i].val));
		if (rc < 0)
			goto fail;
	}

	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(futex), 3,
		SCMP_A1(SCMP_CMP_EQ, FUTEX_WAKE_PRIVATE),
		SCMP_A2(SCMP_CMP_EQ, 2),
		SCMP_A3(SCMP_CMP_EQ, NULL));
	if (rc < 0)
		goto fail;

	rc = seccomp_syscall_priority(ctx, SCMP_SYS(futex), 100);
	if (rc < 0)
		goto fail;

	/* set_robust_list */
	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(set_robust_list), 1,
		SCMP_A1(SCMP_CMP_EQ, 24));
	if (rc < 0)
		goto fail;

	rc = seccomp_syscall_priority(ctx, SCMP_SYS(set_robust_list), 50);
	if (rc < 0)
		goto fail;

	/* setrlimit */
	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setrlimit), 1,
		SCMP_A0(SCMP_CMP_EQ, RLIMIT_CORE));
	if (rc < 0)
		goto fail;

	rc = seccomp_syscall_priority(ctx, SCMP_SYS(setrlimit), 50);
	if (rc < 0)
		goto fail;

	/* getrlimit */
	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getrlimit), 1,
		SCMP_A0(SCMP_CMP_EQ, RLIMIT_STACK));
	if (rc < 0)
		goto fail;

	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getrlimit), 1,
		SCMP_A0(SCMP_CMP_EQ, RLIMIT_CORE));
	if (rc < 0)
		goto fail;

	rc = seccomp_syscall_priority(ctx, SCMP_SYS(getrlimit), 50);
	if (rc < 0)
		goto fail;

	/* eventfd2 */
	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(eventfd2), 2,
		SCMP_A0(SCMP_CMP_EQ, 0),
		SCMP_A1(SCMP_CMP_EQ, O_NONBLOCK|O_CLOEXEC));
	if (rc < 0)
		goto fail;

	rc = seccomp_syscall_priority(ctx, SCMP_SYS(eventfd2), 50);
	if (rc < 0)
		goto fail;

	/* rt_sigprocmask */
	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigprocmask), 3,
		SCMP_A0(SCMP_CMP_EQ, SIG_UNBLOCK),
		SCMP_A2(SCMP_CMP_EQ, NULL),
		SCMP_A3(SCMP_CMP_EQ, 8));
	if (rc < 0)
		goto fail;

	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigprocmask), 1,
		SCMP_A0(SCMP_CMP_EQ, SIG_SETMASK));
	if (rc < 0)
		goto fail;

	rc = seccomp_syscall_priority(ctx, SCMP_SYS(rt_sigprocmask), 50);
	if (rc < 0)
		goto fail;

	/* rt_sigaction */
	const int sigaction_signal_array[13] = {
		SIGALRM,
		SIGCHLD,
		SIGCONT,
		SIGFPE,
		SIGHUP,
		SIGINT,
		SIGPIPE,
		SIGQUIT,
		SIGTERM,
		SIGTRAP,
		SIGUSR1,
		SIGUSR2,
		SIGWINCH
	};
	for (i = 0; i < 13; i++) {
		rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigaction), 2,
			SCMP_A0(SCMP_CMP_EQ, sigaction_signal_array[i]),
			SCMP_A3(SCMP_CMP_EQ, 8));
		if (rc < 0)
			goto fail;
	}

	rc = seccomp_syscall_priority(ctx, SCMP_SYS(rt_sigaction), 50);
	if (rc < 0)
		goto fail;

	/* sendto */
	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendto), 4,
		SCMP_A0(SCMP_CMP_GE, 4),
		SCMP_A3(SCMP_CMP_EQ, 0),
		SCMP_A4(SCMP_CMP_EQ, NULL),
		SCMP_A5(SCMP_CMP_EQ, 0));
	if (rc < 0)
		goto fail;

	rc = seccomp_syscall_priority(ctx, SCMP_SYS(sendto), 70);
	if (rc < 0)
		goto fail;

	/* recvfrom */
	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(recvfrom), 5,
		SCMP_A0(SCMP_CMP_GE, 4),
		SCMP_A2(SCMP_CMP_EQ, 8),
		SCMP_A3(SCMP_CMP_EQ, 0),
		SCMP_A4(SCMP_CMP_EQ, NULL),
		SCMP_A5(SCMP_CMP_EQ, NULL));
	if (rc < 0)
		goto fail;

	rc = seccomp_syscall_priority(ctx, SCMP_SYS(recvfrom), 70);
	if (rc < 0)
		goto fail;

	/* access */
	const int access_mode_array[3] = {
		R_OK,
		F_OK,
		X_OK
	};
	for (i = 0; i < 3; i++) {
		rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(access), 1,
			SCMP_A1(SCMP_CMP_EQ, access_mode_array[i]));
		if (rc < 0)
			goto fail;
	}

	rc = seccomp_syscall_priority(ctx, SCMP_SYS(access), 60);
	if (rc < 0)
		goto fail;

	/* write */
	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 2,
		SCMP_A0(SCMP_CMP_LT, 3),
		SCMP_A2(SCMP_CMP_LE, 4096));
	if (rc < 0)
		goto fail;

	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 2,
		SCMP_A0(SCMP_CMP_GT, 3),
		SCMP_A2(SCMP_CMP_LE, 4096));
	if (rc < 0)
		goto fail;

	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 2,
		SCMP_A0(SCMP_CMP_EQ, 3),
		/* SCMP_A1(SCMP_CMP_EQ, "\1\0\0\0\0\0\0\0"), */
		SCMP_A2(SCMP_CMP_EQ, 8));
	if (rc < 0)
		goto fail;

	rc = seccomp_syscall_priority(ctx, SCMP_SYS(write), 200);
	if (rc < 0)
		goto fail;

	/* read */
	struct read_struct_t {
		int fd;
		size_t count;
	};
	const struct read_struct_t read_struct[6] = {
		{ 0, 256  },
		{ 3, 16   },
		{ 3, 512  },
		{ 3, 832  },
		{ 3, 4000 },
		{ 3, 4096 }
	};
	for (i = 0; i < 6; i++) {
		rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 2,
			SCMP_A0(SCMP_CMP_EQ, read_struct[i].fd),
			SCMP_A2(SCMP_CMP_EQ, read_struct[i].count));
		if (rc < 0)
			goto fail;
	}

	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 1,
		SCMP_A1(SCMP_CMP_GE, 4));
	if (rc < 0)
		goto fail;

	rc = seccomp_syscall_priority(ctx, SCMP_SYS(read), 200);
	if (rc < 0)
		goto fail;

	/* open */
	const int open_flag_array[6] = {
		O_RDONLY,
		O_RDONLY|O_CLOEXEC,
		O_RDONLY|O_NOCTTY|O_NONBLOCK,
		O_WRONLY|O_CREAT|O_APPEND,
		O_WRONLY|O_CREAT|O_TRUNC,
		O_RDWR|O_CREAT|O_TRUNC
	};
	for (i = 0; i < 6; i++) {
		rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 1,
			SCMP_A1(SCMP_CMP_EQ, open_flag_array[i]));
		if (rc < 0)
			goto fail;
	}

	rc = seccomp_syscall_priority(ctx, SCMP_SYS(open), 60);
	if (rc < 0)
		goto fail;

	/* openat */
	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat), 2,
		SCMP_A0(SCMP_CMP_EQ, AT_FDCWD),
		SCMP_A2(SCMP_CMP_EQ, O_RDONLY|O_NONBLOCK|O_DIRECTORY|O_CLOEXEC));
	if (rc < 0)
		goto fail;

	rc = seccomp_syscall_priority(ctx, SCMP_SYS(openat), 50);
	if (rc < 0)
		goto fail;

	/* readlink */
	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(readlink), 1,
		SCMP_A2(SCMP_CMP_EQ, 4095));
	if (rc < 0)
		goto fail;

	rc = seccomp_syscall_priority(ctx, SCMP_SYS(readlink), 50);
	if (rc < 0)
		goto fail;

	/* getdents */
	rc = seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EBADF), SCMP_SYS(getdents), 1,
		SCMP_A2(SCMP_CMP_EQ, 32768));
	if (rc < 0)
		goto fail;

	rc = seccomp_syscall_priority(ctx, SCMP_SYS(getdents), 70);
	if (rc < 0)
		goto fail;

	/* clock_gettime */
	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clock_gettime), 1,
		SCMP_A0(SCMP_CMP_EQ, CLOCK_PROCESS_CPUTIME_ID));
	if (rc < 0)
		goto fail;

	rc = seccomp_syscall_priority(ctx, SCMP_SYS(clock_gettime), 60);
	if (rc < 0)
		goto fail;

	/* getrusage */
	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getrusage), 1,
		SCMP_A0(SCMP_CMP_EQ, 0)); /* RUSAGE_SELF */
	if (rc < 0)
		goto fail;

	rc = seccomp_syscall_priority(ctx, SCMP_SYS(getrusage), 50);
	if (rc < 0)
		goto fail;

	/* select */
	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(select), 2,
		SCMP_A2(SCMP_CMP_EQ, NULL),
		SCMP_A3(SCMP_CMP_EQ, NULL));
	if (rc < 0)
		goto fail;

	rc = seccomp_syscall_priority(ctx, SCMP_SYS(poll), 200);
	if (rc < 0)
		goto fail;

	/* poll */
	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(poll), 2,
		SCMP_A1(SCMP_CMP_LE, 3),
		SCMP_A2(SCMP_CMP_GE, 0),
		SCMP_A2(SCMP_CMP_LE, 1000));
	if (rc < 0)
		goto fail;

	rc = seccomp_syscall_priority(ctx, SCMP_SYS(poll), 200);
	if (rc < 0)
		goto fail;

	/* wait4 */
	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(wait4), 2,
		SCMP_A2(SCMP_CMP_EQ, WNOHANG),
		SCMP_A3(SCMP_CMP_EQ, NULL));
	if (rc < 0)
		goto fail;

	rc = seccomp_syscall_priority(ctx, SCMP_SYS(wait4), 50);
	if (rc < 0)
		goto fail;

	/* tgkill */
	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(tgkill), 2,
		SCMP_A0(SCMP_CMP_EQ, getpid()),
		SCMP_A2(SCMP_CMP_EQ, SIGABRT));
	if (rc < 0)
		goto fail;

	rc = seccomp_syscall_priority(ctx, SCMP_SYS(tgkill), 50);
	if (rc < 0)
		goto fail;

	/* apply filters */
	rc = seccomp_load(ctx);
	if (rc < 0)
		goto fail;

	/* seccomp has been seccessfully loaded and is now enforced */
	return;

fail:
	seccomp_release(ctx);
	fprintf(stderr, "Could not load the sandbox (libseccomp error %d)\n", -rc);
	exit(1);
}
