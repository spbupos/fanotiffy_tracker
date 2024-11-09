#include <ctime>
#include <climits>
#include <future>
#include <vector>
#include <sstream>
#include "headers.h"

/* WARNING: DO NOT ADD DEBUG OUTPUT ON CONSOLE WITH HISTORY KEEPING
 *  EVERY PRRINTF WILL BE WRITTEN TO HISTORY FILE AND RE-TRIGGERED
 */

void EventProcess::determiner(fanotify_event_metadata *event, std::ostream& lout) const {
    std::string path, process, device, base64_content;
    int uid, type = INT_MAX;
    time_t timestamp = time(nullptr);

    int ret = get_file_path_from_fd(event->fd, path);
    get_program_name_from_pid(event->pid, process);
    get_device_path(path, device);
    get_program_owner_from_pid(event->pid, uid);
    get_file_content(path, base64_content); // currently causes performance issues, see main.cpp:76

    if (!ret) // file was deleted
        type = 2;
    else if (event->mask & FAN_ACCESS)
        type = 0;
    else if (event->mask & FAN_MODIFY)
        type = 1;
    if (type == INT_MAX || !type && only_writes)
        goto close;

write:
    /* Output in next format, directly to 'std::ostream& out'
     * '\0'timestamp'\0'path'\0'device'\0'type'\0'process'\0'uid'\0'base64_content'\0'
     */
    lout << '\0' << timestamp << '\0' << path << '\0'
         << device << '\0' << type << '\0' << process
         << '\0' << uid << '\0' << base64_content << '\0'
         << '\n';

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

    // async run of multi-event parsing (because in cases of deletion
    // fd symlinks destroyed faster than I can read content)
    /*std::vector<std::future<std::string>> futures;
    auto *metadata = reinterpret_cast<fanotify_event_metadata *>(buf);
    while (FAN_EVENT_OK(metadata, len)) {
        futures.push_back(std::async(std::launch::async, [this, metadata]() -> std::string {
            std::ostringstream oss;
            this->determiner(metadata, oss);
            return oss.str();
        }));
        metadata = FAN_EVENT_NEXT(metadata, len);
    }

    for (auto &f : futures)
        out << f.get();*/
    // single-threaded version
    auto *metadata = reinterpret_cast<fanotify_event_metadata *>(buf);
    while (FAN_EVENT_OK(metadata, len)) {
        determiner(metadata, out);
        metadata = FAN_EVENT_NEXT(metadata, len);
    }
}
