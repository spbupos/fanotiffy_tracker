#include <ctime>
#include "headers.h"

/* WARNING: DO NOT ADD DEBUG OUTPUT ON CONSOLE WITH HISTORY KEEPING
 *  EVERY PRRINTF WILL BE WRITTEN TO HISTORY FILE AND RE-TRIGGERED
 */

void EventProcess::determiner(fanotify_event_metadata *event) {
    std::string path, process, device, base64_content;
    int uid, type;
    time_t timestamp = time(nullptr);

    get_file_path_from_fd(event->fd, path);
    get_program_name_from_pid(event->pid, process);
    get_device_path(path, device);
    get_program_owner_from_pid(event->pid, uid);
    if (!get_file_content(path, base64_content)) {
        // if can't get content of file, it's deleted
        type = 2;
        goto write;
    }

    type = event->mask & (FAN_MODIFY) ? 1 : 0; // 0 - read, 1 - write, 2 - deleted
    if (!type && only_writes)
        goto close;

write:
    /* Output in next format, directly to 'std::ostream& out'
     * '\0'timestamp'\0'path'\0'device'\0'type'\0'process'\0'uid'\0'base64_content'\0'
     */
    std::cout << '\0' << timestamp << '\0' << path << '\0'
        << device << '\0' << type << '\0' << process
        << '\0' << uid << '\0' << base64_content << '\0'
        << std::endl;

close:
    close(event->fd);
}


void EventProcess::handle_events(int fanotify_fd) {
    char buf[EVENT_BUF_LEN];

    ssize_t len = read(fanotify_fd, buf, sizeof(buf)); // here C-style read is used because it's a system call
    if (len < 1 && errno != EAGAIN) {
        perror("read");
        exit(EXIT_FAILURE);
    }

    auto *metadata = reinterpret_cast<fanotify_event_metadata *>(buf);
    while (FAN_EVENT_OK(metadata, len)) {
        determiner(metadata);
        metadata = FAN_EVENT_NEXT(metadata, len);
    }
}
