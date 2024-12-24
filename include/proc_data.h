#ifndef PROC_DATA_H
#define PROC_DATA_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <stdbool.h> 


#define MAX_PATH_LEN 1024

/*----------------------可视化部分--------------------------------*/
int lookup_txt_file(char *txt_file_path, const char *name, FILE **txt_file) {
    // 检查输入参数
    if (txt_file_path == NULL || name == NULL || txt_file == NULL) {
        fprintf(stderr, "Invalid input arguments\n");
        return -1;
    }

    // 构造完整文件路径
    char full_file_path[MAX_PATH_LEN];
    snprintf(full_file_path, sizeof(full_file_path), "%s/%s.txt", txt_file_path, name);

    // 检查文件是否存在
    struct stat st;
    if (stat(full_file_path, &st) == 0) {
        // 文件存在，尝试打开
        *txt_file = fopen(full_file_path, "r+"); // 以读写模式打开
        if (*txt_file == NULL) {
            perror("Error opening existing file");
            return -1;
        }
    } else {
        // 文件不存在，创建新文件
        *txt_file = fopen(full_file_path, "w+"); // 以读写模式创建文件
        if (*txt_file == NULL) {
            perror("Error creating new file");
            return -1;
        }
    }

    return 0; // 成功
}

// 辅助函数：检查目录是否存在，如果不存在则创建
int ensure_directory_exists(const char *path) {
    struct stat st;
    if (stat(path, &st) == 0) {
        if (S_ISDIR(st.st_mode)) {
            return 0; // 目录已存在
        } else {
            fprintf(stderr, "Error: %s exists but is not a directory\n", path);
            return -1;
        }
    }

    // 目录不存在，尝试创建
    if (mkdir(path, 0755) != 0) {
        perror("Error creating directory");
        return -1;
    }
    return 0;
}

// 辅助函数：在指定目录中创建 CSV 文件
FILE *create_csv_in_folder(const char *folder_path, const char *csv_name) {
    char csv_path[MAX_PATH_LEN];
    snprintf(csv_path, MAX_PATH_LEN, "%s/%s", folder_path, csv_name);

    FILE *file = fopen(csv_path, "a"); // 使用 "a" 模式，文件不存在时会创建
    if (file == NULL) {
        perror("Error creating CSV file");
    }
    return file;
}

// 主函数：创建 run 文件夹并管理 CSV 文件
int visual_create_run_file(char *csv_folder_path, const char *csv_names[], int num_csv_names, FILE *csv_files[]) {
    char run_folder_path[MAX_PATH_LEN];
    snprintf(run_folder_path, MAX_PATH_LEN, "%s/visualize/run", csv_folder_path);

    // 确保 run 文件夹存在
    if (ensure_directory_exists(run_folder_path) != 0) {
        return -1;
    }

    // 遍历 csv_names，创建 CSV 文件并关联到 csv_files
    for (int i = 0; i < num_csv_names; i++) {
        csv_files[i] = create_csv_in_folder(run_folder_path, csv_names[i]);
        if (csv_files[i] == NULL) {
            fprintf(stderr, "Error: Failed to create or open %s/%s\n", run_folder_path, csv_names[i]);
            return -1;
        }
    }

    return 0;
}
#endif