#include "headers.h"


void determiner(struct fanotify_event_metadata *event) {
    char path[PATH_MAX];
    int uid;

    printf("Event in path: %s\n",
        get_file_path_from_fd(event->fd, path, PATH_MAX)
        ? path : "unknown");
    printf("Event for process: %s\n",
        get_program_name_from_pid(event->pid, path, PATH_MAX)
        ? path : "unknown");
    printf("Proccess owner: %d\n",
        get_program_owner_from_pid(event->pid, &uid)
        ? uid : -1);

    printf("Event type: ");
    if (event->mask & FAN_ACCESS)
        printf ("Read\n");
    else if (event->mask & FAN_MODIFY)
        printf ("Write\n");

    close(event->fd);
}


void handle_events(int fanotify_fd) {
    char buf[EVENT_BUF_LEN];
    ssize_t len;
    struct fanotify_event_metadata *metadata;

    len = read(fanotify_fd, buf, sizeof(buf));
    if (len < 1 && errno != EAGAIN) {
        perror("read");
        exit(EXIT_FAILURE);
    }

    metadata = (struct fanotify_event_metadata *)buf;
    while (FAN_EVENT_OK(metadata, len)) {
        determiner(metadata);
        metadata = FAN_EVENT_NEXT(metadata, len);
    }
}