#pragma once

#include <time.h>
struct ntp_header {
    struct timespec timestamp1;
    struct timespec timestamp2;
    struct timespec timestamp3;
    struct timespec timestamp4;
};