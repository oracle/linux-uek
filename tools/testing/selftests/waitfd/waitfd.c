/* waitfd testcase. */

#define _GNU_SOURCE 1
#include <linux/unistd.h>
#include <sys/syscall.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <poll.h>

int waitfd(int which, pid_t upid, int options, int flags)
{
        return syscall(__NR_waitfd, which, upid, options, flags);
}

void sleeper(void)
{
	sleep(10);
	exit(0);
}

int main (void)
{
        pid_t die_pid, ptrace_pid;
        int die_fd, ptrace_fd;
        siginfo_t info;
	struct pollfd pfd[2];
        int procs_left = 2;

	memset(pfd, 0, sizeof(pfd));

        /*
         * Fork off two children, one of which waits for a ptrace().
         * Both just sleep after that.
         */

        die_pid = fork();

        if (die_pid == 0)
                sleeper();

        ptrace_pid = fork();
        if (ptrace_pid == 0) {
                ptrace(PTRACE_TRACEME, 0, 0, 0);
                sleeper();
        }

        die_fd = waitfd(P_PID, die_pid, WEXITED | WSTOPPED, 0);
        ptrace_fd = waitfd(P_PID, ptrace_pid, WEXITED | WSTOPPED, 0);

        if (die_fd < 0 || ptrace_fd < 0) {
                perror("Cannot waitfd()");
                exit(1);
        }

        pfd[0].fd = die_fd;
        pfd[0].events = POLLIN;
        pfd[1].fd = ptrace_fd;
        pfd[1].events = POLLIN;

        /*
         * Hit the ptrace PID with a signal
         */
        kill(ptrace_pid, SIGABRT);

        while (procs_left > 0) {
                ssize_t bytes;

                if (poll(pfd, 2, -1) < 0)
                        perror ("poll() failed");

                if (pfd[0].revents != 0) {
                        if ((bytes = read(die_fd, &info, sizeof (siginfo_t))) < sizeof (siginfo_t)) {
                                fprintf(stderr, "Only read %zi bytes\n", bytes);
                                exit(1);
                        }

                        printf("die_fd returned code %i, status %i via waitfd read: revents are %x\n", info.si_code, info.si_status, pfd[0].revents);
                        pfd[0].fd *= -1;
                        procs_left--;
                }

                if (pfd[1].revents != 0) {
                        memset(&info, 0, sizeof (siginfo_t));
                        waitid(P_PID, ptrace_pid, &info, WEXITED | WSTOPPED | WNOHANG);
                        if (info.si_pid != ptrace_pid) {
                                fprintf(stderr, "waitfd said PID %i was ready, but waitid() says it isn't: %i\n",
                                    ptrace_pid, info.si_pid);
                                exit(1);
                        }
                        printf("ptrace_fd returned code %i, status %i via waitid; revents are %x\n", info.si_code, info.si_status, pfd[1].revents);
                        pfd[1].fd *= -1;
                        procs_left--;
                }
        }

        return 0;
}
