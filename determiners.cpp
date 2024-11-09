#include <string>
#include <sstream>
#include <filesystem>
#include <sys/stat.h>
#include <fstream>
#include "headers.h"

bool Determiners::get_program_name_from_pid(int pid, std::string &buffer) {
    /* Try to get program name by PID */
    std::stringstream ss;
    ss << "/proc/" << pid << "/exe";

    // PID may be killed before we get it's name
    try {
        const std::filesystem::path path = std::filesystem::canonical(ss.str());
        buffer = path.string();
    } catch (std::filesystem::filesystem_error&) {
        buffer = "(killed)";
        return false;
    }
    return true;
}

bool Determiners::get_program_owner_from_pid(int pid, int &buffer) {
    /* Try to get program owner by PID */
    std::stringstream ss;
    ss << "/proc/" << pid << "/loginuid";

    std::ifstream file(ss.str());
    if (!file.is_open()) {
        buffer = -1;
        return false;
    }

    long long sb; // UID may be 2^32-1, which actually means 0 (root), but can't be directly read into int
    file >> sb;
    file.close();

    buffer = int(sb);
    if (buffer < 0)
        buffer = 0;

    return true;
}

bool Determiners::get_file_path_from_fd(int fd, std::string &buffer) {
    if (fd <= 0)
        return false;

    std::stringstream ss;
    ss << "/proc/self/fd/" << fd;
    // PID may be killed before we get it's name
    try {
        const std::filesystem::path path = std::filesystem::canonical(ss.str());
        buffer = path.string();
    } catch (std::filesystem::filesystem_error&) {
        buffer = std::string("(killed)");
        return false;
    }

    return true;
}

bool Determiners::get_device_path(const std::string &mount_point, std::string &buffer) {
    struct stat sb{};
    if (stat(mount_point.c_str(), &sb) == -1) {
        buffer = "(killed)";
        return false;
    }

    int major_dev = major(sb.st_dev), minor_dev = minor(sb.st_dev);
    std::stringstream ss;
    ss << "/dev/block/" << major_dev << ":" << minor_dev;

    const std::filesystem::path path = std::filesystem::canonical(ss.str());

    buffer = path.string();
    return true;
}

bool Determiners::get_file_content(const std::string &path, std::string &buffer) {
    /* open file in binary mode, determine it's length
     * if file is bigger than 100 bytes, read 100 bytes in middle of file
     * if file size is between 20 and 100 bytes, read 20 bytes in middle of file
     * if file is smaller than 20 bytes, read all bytes
     * starting pos = (file size - reading length) / 2
     */
    size_t len;
    try {
        len = std::filesystem::file_size(path);
    } catch (std::filesystem::filesystem_error&) {
        buffer = "(deleted)";
        return false;
    }
    if (len == 0) {
        buffer = "(empty)";
        return true;
    }
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open())
        return false;

    int reading = len > 100 ? 100 : (len > 20 ? 20 : len);
    unsigned char subbufer[100];
    file.seekg(static_cast<std::streamoff>(len - reading) / 2);
    file.read(reinterpret_cast<std::istream::char_type *>(subbufer), reading);
    file.close();

    // encode bytes from subbufer to base64 string
    buffer = base64_encode(subbufer, reading);
    return true;
}
