#ifndef HEADERS_H
#define HEADERS_H

#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <linux/limits.h>
#include <stdlib.h>
#include <errno.h>
#include <linux/fanotify.h>

#define EVENT_SIZE (sizeof(struct fanotify_event_metadata))
#define EVENT_BUF_LEN (1024 * (EVENT_SIZE + 16))

int get_program_name_from_pid(int pid, char *buffer, size_t buffer_size);
int get_program_owner_from_pid(int pid, int *buffer);
int get_file_path_from_fd(int fd, char *buffer, size_t buffer_size);

void handle_events(int fanotify_fd);

#endif //HEADERS_H
