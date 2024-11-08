#include <sys/fanotify.h>
#include <poll.h>
#include "headers.h"


void main(int argc, char *argv[]) {
    int fanotify_fd;
    struct pollfd fds;
    const char mount_point[] = "/";

    fanotify_fd = fanotify_init(FAN_CLOEXEC | FAN_CLASS_CONTENT, O_RDONLY);
    if (fanotify_fd == -1) {
        perror("fanotify_init");
        exit(EXIT_FAILURE);
    }

    if (fanotify_mark(fanotify_fd, FAN_MARK_ADD | FAN_MARK_MOUNT,
        FAN_ACCESS | FAN_MODIFY | FAN_EVENT_ON_CHILD, AT_FDCWD, mount_point)) {
        perror("fanotify_mark");
        exit(EXIT_FAILURE);
    }

    fds.fd = fanotify_fd;
    fds.events = POLLIN;

    printf("Monitoring file system events...\n");

    while (1) {
        int poll_num = poll(&fds, 1, -1);
        if (poll_num == -1) {
            perror("poll");
            exit(EXIT_FAILURE);
        }

        if (fds.revents & POLLIN)
            handle_events(fanotify_fd);
    }
}
