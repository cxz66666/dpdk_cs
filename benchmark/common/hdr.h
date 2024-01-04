#include <hdr/hdr_histogram.h>
#include <assert.h>
struct hdr_histogram *latency_hist;
void init_hdr() {
    int ret = hdr_init(1, 1000 * 1000 * 10, 3,
        &latency_hist);
    assert(ret == 0);
}

void close_hdr() {
    hdr_close(latency_hist);
}

bool write_hdr_result(char *filename) {
    FILE *fp = fopen(filename, "w");

    if (fp == NULL) {
        return false;
    }

    hdr_percentiles_print(latency_hist, fp, 5, 10, CLASSIC);
    fclose(fp);
    hdr_reset(latency_hist);
    return true;
}