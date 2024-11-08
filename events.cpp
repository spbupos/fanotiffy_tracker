#include <string>
#include <cstring>
#include <cstddef>
#include <sstream>
#include <filesystem>
#include <sys/stat.h>
#include "headers.h"


bool EventProcess::get_program_name_from_pid(int pid, std::string &buffer) {
    /* Try to get program name by PID */
    std::stringstream ss;
    ss << "/proc/" << pid << "/cmdline";

    std::ifstream file(ss.str());
    if (!file.is_open())
        return false;
    file >> buffer;
    file.close();

    /* split the string by "^@" */
    size_t pos = buffer.find('\0');
    if (pos != std::string::npos)
        buffer = buffer.substr(0, pos);

    return true;
}


bool EventProcess::get_program_owner_from_pid(int pid, int &buffer) {
    /* Try to get program owner by PID */
    std::stringstream ss;
    ss << "/proc/" << pid << "/loginuid";

    std::ifstream file(ss.str());
    if (!file.is_open())
        return false;

    long long sb; // UID may be 2^32-1, which actually means 0 (root), but can't be directly read into int
    file >> sb;
    file.close();

    buffer = int(sb);
    if (buffer < 0)
        buffer = 0;

    return true;
}


bool EventProcess::get_file_path_from_fd(int fd, std::string &buffer) {
    if (fd <= 0)
        return false;

    std::stringstream ss;
    ss << "/proc/self/fd/" << fd;
    const std::filesystem::path path = std::filesystem::canonical(ss.str());

    buffer = path.string();
    return true;
}


bool get_device_name(const std::string &mount_point, std::string &buffer) {
    struct stat sb{};
    if (stat(mount_point.c_str(), &sb) == -1)
        return false;

    buffer = std::to_string(sb.st_dev);
    return true;
}


void EventProcess::determiner(fanotify_event_metadata *event) {
    std::string path, process, device_name;
    int uid;

    get_file_path_from_fd(event->fd, path);
    get_program_name_from_pid(event->pid, process);
    get_device_name(path, device_name);
    get_program_owner_from_pid(event->pid, uid);
    int type = event->mask & (FAN_ACCESS) ? 0 : 1; // 0 - read, 1 - write

    // may be replaced with writing to a file or stream
    out << "Process: " << process << " (PID: " << event->pid << ", UID: " << uid << ")" << std::endl
        << "File: " << path << " (on device: " << device_name << ")" << std::endl
        << "Type: " << (type == 0 ? "Read" : "Write") << std::endl;

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
