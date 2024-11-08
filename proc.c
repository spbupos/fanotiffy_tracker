#include <stddef.h>
#include <string.h>
#include "headers.h"


int get_program_name_from_pid(int pid, char *buffer, size_t buffer_size)
{
    int fd;
    ssize_t len;
    char *aux;

    /* Try to get program name by PID */
    sprintf(buffer, "/proc/%d/cmdline", pid);
    if ((fd = open (buffer, O_RDONLY)) < 0)
        return 0;

    /* Read file contents into buffer */
    len = read(fd, buffer, buffer_size - 1);
    close(fd);
    if (len <= 0)
        return 0;

    buffer[len] = '\0';
    aux = strstr(buffer, "^@");
    if (aux)
        *aux = '\0';

    return 1;
}


int get_program_owner_from_pid(int pid, int *buffer)
{
    int fd;
    ssize_t len;
    char *aux;
    char s_buffer[100];

    /* Try to get program owner by PID */
    sprintf(s_buffer, "/proc/%d/loginuid", pid);
    if ((fd = open(s_buffer, O_RDONLY)) < 0)
        return 0;

    /* Read file contents into buffer */
    len = read(fd, s_buffer, 99);
    close(fd);
    if (len <= 0)
        return 0;
    s_buffer[len] = '\0';

    *buffer = (int)atoll(s_buffer);
    if (*buffer < 0)
        *buffer = 0;

    return 1;
}


int get_file_path_from_fd(int fd, char *buffer, size_t buffer_size)
{
    ssize_t len;

    if (fd <= 0)
        return 0;

    sprintf(buffer, "/proc/self/fd/%d", fd);
    if ((len = readlink(buffer, buffer, buffer_size - 1)) < 0)
        return 0;

    buffer[len] = '\0';
    return 1;
}