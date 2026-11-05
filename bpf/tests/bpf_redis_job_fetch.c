// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <generictracer/redis_job_fetch.h>

enum { k_captured_len = 128 };

static int failures;

static void expect(bool condition, const char *message) {
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", message);
        failures++;
    }
}

static enum redis_job_fetch request(const char *resp) {
    unsigned char buf[256] = {};
    const size_t len = strlen(resp);
    memcpy(buf, resp, len);
    return redis_job_fetch_request(buf, len);
}

static bool has_captured_job(enum redis_job_fetch fetch, const char *resp, size_t captured) {
    unsigned char buf[k_captured_len] = {};
    size_t len = strlen(resp);
    if (len > captured) {
        len = captured;
    }
    memcpy(buf, resp, len);
    return redis_job_fetch_reply_has_job(fetch, buf, len);
}

static bool has_job(enum redis_job_fetch fetch, const char *resp) {
    return has_captured_job(fetch, resp, k_captured_len);
}

static void test_requests(void) {
    static const char *const fetches[] = {
        "*3\r\n$5\r\nBLPOP\r\n$5\r\njobs:\r\n$1\r\n0\r\n",
        "*3\r\n$5\r\nbrpop\r\n$5\r\njobs:\r\n$1\r\n5\r\n",
        "*2\r\n$4\r\nLPOP\r\n$4\r\njobs\r\n",
        "*2\r\n$4\r\nrpop\r\n$4\r\njobs\r\n",
        "*3\r\n$9\r\nRPOPLPUSH\r\n$4\r\njobs\r\n$4\r\nwork\r\n",
        "*4\r\n$10\r\nBRPOPLPUSH\r\n$4\r\njobs\r\n$4\r\nwork\r\n$1\r\n0\r\n",
        "*6\r\n$6\r\nBLMOVE\r\n$4\r\njobs\r\n$4\r\nwork\r\n$4\r\nLEFT\r\n$5\r\nRIGHT\r\n$"
        "1\r\n0\r\n",
        "*5\r\n$5\r\nLMOVE\r\n$4\r\njobs\r\n$4\r\nwork\r\n$4\r\nLEFT\r\n$5\r\nRIGHT\r\n",
        "*4\r\n$5\r\nLMPOP\r\n$1\r\n1\r\n$4\r\njobs\r\n$4\r\nLEFT\r\n",
        "*5\r\n$6\r\nBLMPOP\r\n$1\r\n0\r\n$1\r\n1\r\n$4\r\njobs\r\n$4\r\nLEFT\r\n",
        "*2\r\n$7\r\nZPOPMIN\r\n$7\r\ndelayed\r\n",
        "*2\r\n$7\r\nzpopmax\r\n$7\r\ndelayed\r\n",
        "*3\r\n$8\r\nBZPOPMIN\r\n$7\r\ndelayed\r\n$1\r\n0\r\n",
        "*3\r\n$8\r\nbzpopmax\r\n$7\r\ndelayed\r\n$1\r\n0\r\n",
        "*4\r\n$5\r\nZMPOP\r\n$1\r\n1\r\n$7\r\ndelayed\r\n$3\r\nMIN\r\n",
        "*5\r\n$6\r\nBZMPOP\r\n$1\r\n0\r\n$1\r\n1\r\n$7\r\ndelayed\r\n$3\r\nMIN\r\n",
        "*4\r\n$5\r\nXREAD\r\n$7\r\nSTREAMS\r\n$6\r\nevents\r\n$1\r\n$\r\n",
        "*7\r\n$10\r\nXREADGROUP\r\n$5\r\nGROUP\r\n$1\r\ng\r\n$1\r\nc\r\n$7\r\nSTREAMS\r\n$"
        "1\r\ns\r\n"
        "$1\r\n>\r\n",
        "*6\r\n$6\r\nXCLAIM\r\n$1\r\ns\r\n$1\r\ng\r\n$1\r\nc\r\n$4\r\n1000\r\n$3\r\n1-0\r\n",
        // 10 or more arguments
        "*12\r\n$5\r\nBLPOP\r\n$1\r\na\r\n$1\r\nb\r\n$1\r\nc\r\n$1\r\nd\r\n$1\r\ne\r\n",
    };
    for (size_t i = 0; i < sizeof(fetches) / sizeof(fetches[0]); i++) {
        if (request(fetches[i]) != k_redis_job_fetch_take) {
            fprintf(stderr, "not a fetch: %s\n", fetches[i]);
            failures++;
        }
    }

    expect(request("*6\r\n$10\r\nXAUTOCLAIM\r\n$1\r\ns\r\n$1\r\ng\r\n$1\r\nc\r\n$1\r\n0\r\n"
                   "$3\r\n0-0\r\n") == k_redis_job_fetch_autoclaim,
           "XAUTOCLAIM has its own reply shape");

    static const char *const others[] = {
        "*2\r\n$3\r\nGET\r\n$4\r\njobs\r\n",
        "*3\r\n$5\r\nLPUSH\r\n$4\r\njobs\r\n$1\r\nx\r\n",
        "*3\r\n$4\r\nLLEN\r\n$4\r\njobs\r\n$1\r\nx\r\n",
        "*3\r\n$6\r\nLRANGE\r\n$4\r\njobs\r\n$1\r\n0\r\n",
        "*3\r\n$7\r\nEVALSHA\r\n$4\r\nabcd\r\n$1\r\n0\r\n",
        "*2\r\n$9\r\nSUBSCRIBE\r\n$4\r\njobs\r\n",
        "*2\r\n$4\r\nXADD\r\n$4\r\njobs\r\n$1\r\nx\r\n",
        // a name that merely starts like a fetch
        "*2\r\n$6\r\nLPOPXX\r\n$4\r\njobs\r\n",
        // inline commands are not RESP arrays
        "BLPOP jobs 0\r\n\r\n\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: x\r\n\r\n",
        // too short to name a command
        "*1\r\n$4\r\nLPOP\r\n",
    };
    for (size_t i = 0; i < sizeof(others) / sizeof(others[0]); i++) {
        if (request(others[i]) != k_redis_job_fetch_none) {
            fprintf(stderr, "a fetch: %s\n", others[i]);
            failures++;
        }
    }
}

static void test_replies(void) {
    expect(has_job(k_redis_job_fetch_take, "*2\r\n$4\r\njobs\r\n$3\r\n101\r\n"), "BLPOP job");
    expect(has_job(k_redis_job_fetch_take, "$3\r\n101\r\n"), "LPOP job");
    expect(has_job(k_redis_job_fetch_take, "$0\r\n\r\n"), "an empty element is still taken");
    expect(has_job(k_redis_job_fetch_take, "*3\r\n$7\r\ndelayed\r\n$3\r\n101\r\n$1\r\n5\r\n"),
           "BZPOPMIN job");
    expect(has_job(k_redis_job_fetch_take, "*1\r\n*2\r\n$1\r\ns\r\n*1\r\n*2\r\n$3\r\n1-0\r\n"),
           "XREADGROUP entries");
    expect(has_job(k_redis_job_fetch_take, "%1\r\n$1\r\ns\r\n*1\r\n*2\r\n$3\r\n1-0\r\n"),
           "RESP3 XREADGROUP entries");

    expect(!has_job(k_redis_job_fetch_take, "*-1\r\n"), "BLPOP timeout");
    expect(!has_job(k_redis_job_fetch_take, "$-1\r\n"), "LPOP on an empty list");
    expect(!has_job(k_redis_job_fetch_take, "_\r\n"), "RESP3 null");
    expect(!has_job(k_redis_job_fetch_take, "*0\r\n"), "empty array");
    expect(!has_job(k_redis_job_fetch_take, "%0\r\n"), "RESP3 empty map");
    expect(!has_job(k_redis_job_fetch_take, "-WRONGTYPE Operation against a key\r\n"), "error");
    expect(!has_job(k_redis_job_fetch_take, "!21\r\nSYNTAX invalid syntax\r\n"),
           "RESP3 blob error");
    expect(!has_job(k_redis_job_fetch_take, "*-"), "too short to tell");

    expect(has_job(k_redis_job_fetch_autoclaim, "*3\r\n$3\r\n0-0\r\n*1\r\n*2\r\n$3\r\n1-0\r\n"),
           "XAUTOCLAIM claimed an entry");
    expect(!has_job(k_redis_job_fetch_autoclaim, "*3\r\n$3\r\n0-0\r\n*0\r\n*0\r\n"),
           "XAUTOCLAIM claimed nothing");
    expect(!has_job(k_redis_job_fetch_autoclaim, "*3\r\n$15\r\n1700000000000-0\r\n*0\r\n*0\r\n"),
           "XAUTOCLAIM with a two digit cursor length claimed nothing");

    char long_cursor[k_captured_len + 64] = "*3\r\n$90\r\n";
    memset(long_cursor + strlen(long_cursor), '9', 90);
    strcat(long_cursor, "\r\n*0\r\n*0\r\n");
    expect(!has_job(k_redis_job_fetch_autoclaim, long_cursor),
           "a cursor that fits shows an empty claim");
    expect(has_captured_job(k_redis_job_fetch_autoclaim, long_cursor, 100),
           "a claim cut off from the captured reply is taken as one");
}

int main(void) {
    test_requests();
    test_replies();
    if (failures) {
        return 1;
    }
    puts("Redis job fetch checks passed");
    return 0;
}
