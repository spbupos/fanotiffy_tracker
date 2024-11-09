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
#include <unordered_set>

#define EVENT_SIZE (sizeof(struct fanotify_event_metadata))
#define EVENT_BUF_LEN (1024 * (EVENT_SIZE + 16))
#define REPORT_MAX_SIZE 712

#define major(dev) ((int)(((unsigned int) (dev) >> 8) & 0xff))
#define minor(dev) ((int)((dev) & 0xff))

std::string base64_encode(unsigned char const* bytes_to_encode, unsigned int in_len);
std::string base64_decode(std::string const& encoded_string);

class Determiners {
    static bool get_program_name_from_pid(int pid, std::string& buffer);
    static bool get_program_owner_from_pid(int pid, int& buffer);
    static bool get_file_path_from_fd(int fd, std::string& buffer);
    static bool get_device_path(const std::string &mount_point, std::string &buffer);
    static bool get_file_content(const std::string &path, std::string &buffer);

    friend class EventProcess;
};

class EventProcess : public Determiners {
    std::ostream& out;
    bool only_writes;

    void determiner(fanotify_event_metadata *event);

public:
    // passing device name from mountpoint scanner for full report
    explicit EventProcess(std::ostream& out, bool only_writes = false) :
        out(out), only_writes(only_writes) {}
    void handle_events(int fanotify_fd);
};

#endif //HEADERS_H
