#ifndef HEADERS_H
#define HEADERS_H

#include <fcntl.h>
#include <iostream>
#include <unistd.h>
#include <linux/limits.h>
#include <cstdlib>
#include <cerrno>
#include <linux/fanotify.h>
#include <fstream>
#include <utility>

#define EVENT_SIZE (sizeof(struct fanotify_event_metadata))
#define EVENT_BUF_LEN (1024 * (EVENT_SIZE + 16))

class EventProcess {
    std::ostream& out;
    bool only_writes;

    static bool get_program_name_from_pid(int pid, std::string& buffer);
    static bool get_program_owner_from_pid(int pid, int& buffer);
    static bool get_file_path_from_fd(int fd, std::string& buffer);
    static bool get_device_path(const std::string &mount_point, std::string &buffer);
    void determiner(fanotify_event_metadata *event);

public:
    // passing device name from mountpoint scanner for full report
    explicit EventProcess(std::ostream& out = std::cout, bool only_writes = false) :
        only_writes(only_writes), out(out) {}
    void handle_events(int fanotify_fd);
};

#endif //HEADERS_H
