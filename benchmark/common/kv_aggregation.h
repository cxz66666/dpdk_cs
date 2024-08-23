#include <stdint.h>
#include <vector>
#include <string>
#include <fstream>
#include <sstream>
#include<iostream>
struct kv_element {
    uint64_t key;
    uint64_t value;
};

std::vector<kv_element> init_kv_elements_dataset(std::string fliename) {
    std::ifstream file(fliename); // 替换为您的文件名
    std::vector<kv_element> res;
    uint64_t max_key = 0;
    if (file.is_open()) {
        std::string line;

        while (std::getline(file, line)) {
            std::istringstream iss(line);
            uint64_t key, value;

            if (iss >> key >> value) {
                res.push_back({ key, value });
            } else {
                std::cout << "Invalid line: " << line << std::endl;
                exit(1);
            }
            max_key = std::max(max_key, key);
        }
    } else {
        std::cout << "Unable to open file: " << fliename << std::endl;
        exit(1);
    }
    std::cout << "max_key: " << max_key << std::endl;
    return res;
}

std::vector<kv_element> init_kv_elements_uniform(size_t number) {
    std::vector<kv_element> res;
    for (size_t i = 0;i < number;i++) {
        res.push_back({ i,1 });
    }
    return res;
}

