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
#include <set>

#define EVENT_SIZE (sizeof(struct fanotify_event_metadata))
#define EVENT_BUF_LEN (1024 * (EVENT_SIZE + 16))

#define major(dev) ((int)(((unsigned int) (dev) >> 8) & 0xff))
#define minor(dev) ((int)((dev) & 0xff))

struct FilePart {
    unsigned char bytes[101];
    size_t len = 0;
};

class Determiners {
    static bool get_program_name_from_pid(int pid, std::string& buffer);
    static bool get_program_owner_from_pid(int pid, int& buffer);
    static bool get_file_path_from_fd(int fd, std::string& buffer);
    static bool get_device_path(const std::string &mount_point, std::string &buffer);
    static bool get_file_content(const std::string &path, FilePart &buffer);

    friend class EventProcess;
};

class EventProcess : public Determiners {
    std::ofstream& out;
    bool only_writes;
    std::set<std::string> ignored_paths;

    void determiner(fanotify_event_metadata *event);

public:
    // passing device name from mountpoint scanner for full report
    explicit EventProcess(std::ofstream& out, bool only_writes = false) :
        only_writes(only_writes), out(out) {}
    void handle_events(int fanotify_fd);

    friend class MountpointMonitor;
};

#endif //HEADERS_H
