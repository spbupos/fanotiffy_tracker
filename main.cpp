#include <sys/fanotify.h>
#include <poll.h>
#include <set>
#include <future>
#include "headers.h"


class MountpointMonitor {
    int fanotify_fd;
    EventProcess *ep;
    pollfd fds{};

public:
    explicit MountpointMonitor(std::ostream& out, bool only_writes = false) {
        ep = new EventProcess(out, only_writes);

        fanotify_fd = fanotify_init(FAN_CLOEXEC | FAN_CLASS_CONTENT, O_RDONLY);
        if (fanotify_fd == -1) {
            perror("fanotify_init");
            exit(EXIT_FAILURE);
        }

        fds.fd = fanotify_fd;
        fds.events = POLLIN;

        add_all_filesystems();
    }

    void add_filesystem(const std::string& mount_point) const {
        if (fanotify_mark(fanotify_fd, FAN_MARK_ADD | FAN_MARK_MOUNT,
            FAN_ACCESS | FAN_MODIFY | FAN_EVENT_ON_CHILD, AT_FDCWD, mount_point.c_str())) {
            perror("fanotify_mark");
            exit(EXIT_FAILURE);
        }
    }

    void add_all_filesystems() const {
        std::ifstream file("/proc/mounts");
        if (!file.is_open()) {
            perror("get_mount_points");
            exit(EXIT_FAILURE);
        }

        std::string line;
        // iterate for each mountpoint
        while (std::getline(file, line)) {
            auto pos_of_first_space = line.find(' ');
            const std::string device_name = line.substr(0, pos_of_first_space);

            // if device name doesn't start with /dev, it's not a device
            if (device_name.find("/dev") != 0)
                continue;

            auto pos_of_second_space = line.find(' ', pos_of_first_space + 1);
            const std::string mount_point = line.substr(pos_of_first_space + 1, pos_of_second_space - pos_of_first_space - 1);

            add_filesystem(mount_point);
        }
    }

    void single_poll() {
        int poll_num = poll(&fds, 1, -1);
        if (poll_num == -1) {
            perror("poll");
            exit(EXIT_FAILURE);
        }

        if (fds.revents & POLLIN)
            ep->handle_events(fanotify_fd);
    }

    void infinite_poll() {
        while (true)
            single_poll();
    }

    ~MountpointMonitor() {
        close(fanotify_fd);
    }
};


int main() {
    // test binary output
    MountpointMonitor mm(std::cout, true);
    mm.infinite_poll();
}
