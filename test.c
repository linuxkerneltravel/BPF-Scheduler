#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/file.h>
#include <unistd.h>

#define FILE_PATH "concerned/comm_attention.txt"

int main() {
    FILE *file;
    int fd;
    const char *data = "stress-ng\n";

    // 打开文件
    file = fopen(FILE_PATH, "a");
    if (file == NULL) {
        fprintf(stderr, "Failed to open file %s: %s\n", FILE_PATH, strerror(errno));
        return EXIT_FAILURE;
    }

    // 获取文件描述符
    fd = fileno(file);

    // 自旋获取写锁
    while (flock(fd, LOCK_EX) != 0) {
        if (errno != EWOULDBLOCK) {
            fprintf(stderr, "Failed to acquire lock: %s\n", strerror(errno));
            fclose(file);
            return EXIT_FAILURE;
        }
        // 等待一段时间再尝试
        usleep(100000);  // 100ms
    }

    // 写入数据
    if (fputs(data, file) == EOF) {
        fprintf(stderr, "Failed to write to file %s: %s\n", FILE_PATH, strerror(errno));
        flock(fd, LOCK_UN);  // 释放锁
        fclose(file);
        return EXIT_FAILURE;
    }

    printf("Successfully wrote '%s' to %s\n", data, FILE_PATH);

    // 释放锁并关闭文件
    flock(fd, LOCK_UN);
    fclose(file);

    return EXIT_SUCCESS;
}
