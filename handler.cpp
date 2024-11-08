#include <ctime>
#include "headers.h"

void EventProcess::determiner(fanotify_event_metadata *event) {
    std::string path, process, device;
    FilePart content{};
    int uid, type;
    time_t timestamp = std::time(nullptr);

    get_program_name_from_pid(event->pid, process);
    get_file_path_from_fd(event->fd, path);
    if (ignored_paths.contains(path))
        goto close;

    get_device_path(path, device);
    get_program_owner_from_pid(event->pid, uid);
    get_file_content(path, content);

    type = event->mask & (FAN_MODIFY) ? 1 : 0; // 0 - read, 1 - write
    if (!type && only_writes)
        goto close;

    /* write binary, format
     * timestamp - 8 bytes (long long)
     * event type - 4 bytes (int)
     * pid - 4 bytes (int)
     * uid - 4 bytes (int)
     * path_length - 4 bytes (int)
     * path - X bytes (char array)
     * process_length - 4 bytes (int)
     * proccess - Y bytes (char array)
     * device_length - 4 bytes (int)
     * device - Z bytes (char array)
     * content_length - 8 bytes (long long)
     * content - W bytes (char array)
     */
    if (out.is_open()) {
        std::cout << "INFO: event in file " << path << std::endl;
        int path_length = path.length(), process_length = process.length(), device_length = device.length();
        size_t content_length = content.len;

        out.write(reinterpret_cast<const char *>(&timestamp), sizeof(timestamp));
        out.write(reinterpret_cast<const char *>(&type), sizeof(type));
        out.write(reinterpret_cast<const char *>(&event->pid), sizeof(event->pid));
        out.write(reinterpret_cast<const char *>(&uid), sizeof(uid));
        out.write(reinterpret_cast<const char *>(&path_length), sizeof(path_length));
        out.write(path.c_str(), path_length);
        out.write(reinterpret_cast<const char *>(&process_length), sizeof(process_length));
        out.write(process.c_str(), process_length);
        out.write(reinterpret_cast<const char *>(&device_length), sizeof(device_length));
        out.write(device.c_str(), device_length);
        out.write(reinterpret_cast<const char *>(&content_length), sizeof(content_length));
        out.write(reinterpret_cast<const char *>(content.bytes), static_cast<std::streamoff>(content_length));
    }

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
