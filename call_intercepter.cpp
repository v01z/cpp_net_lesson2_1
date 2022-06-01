//nc -u -l -p 11111
//LD_PRELOAD=./libcall-intercepter.so nc -u localhost 11111

#if !defined(_GNU_SOURCE)
#   define _GNU_SOURCE
#endif

//
// System calls interceptor for the networking spoiling...
//

extern "C"
{
#include <dlfcn.h>
#include <unistd.h>
}

#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <fstream>


static void init (void) __attribute__ ((constructor));

typedef ssize_t (*write_t)(int fd, const void *buf, size_t count);
typedef int (*socket_t)(int domain, int type, int protocol);
typedef int (*close_t)(int fd);

static close_t old_close;
static socket_t old_socket;
static write_t old_write;

static int socket_fd = -1;

void init(void)
{
    printf("Interceptor library loaded.\n");

    old_close = reinterpret_cast<close_t>(dlsym(RTLD_NEXT, "close"));
    old_write = reinterpret_cast<write_t>(dlsym(RTLD_NEXT, "write"));
    old_socket = reinterpret_cast<socket_t>(dlsym(RTLD_NEXT, "socket"));
}

extern "C"
{

int close(int fd)
{
    if (fd == socket_fd)
    {
        printf("> close() on the socket was called!\n");
        socket_fd = -1;
    }

    return old_close(fd);
}

ssize_t write(int fd, const void *buf, size_t count)
{
    auto char_buf = reinterpret_cast<const char*>(buf);

    std::ofstream logfile;
    logfile.open("log.txt", std::ios_base::app);

    if (char_buf && (count > 1) && (fd == socket_fd))
    {
        printf("> write() on the socket was called with a string!\n");

        for (size_t i = 0; i < count - 1; ++i)
        {
            char *c = const_cast<char *>(char_buf) + i;

            logfile << *c;
        }
        logfile << '\n';
    }

   return old_write(fd, buf, count);
}

int socket(int domain, int type, int protocol)
{
    int cur_socket_fd = old_socket(domain, type, protocol);

    if (-1 == socket_fd)
    {
        printf("> socket() was called, fd = %d!\n", cur_socket_fd);
        socket_fd = cur_socket_fd;
    }
    else
    {
        printf("> socket() was called, but socket was opened already...\n");
    }

    return cur_socket_fd;
}

} // extern "C"

