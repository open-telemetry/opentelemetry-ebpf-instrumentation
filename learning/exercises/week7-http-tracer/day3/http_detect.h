// Week 7 - Day 3: HTTP 协议检测头文件
// 参考: OBI 的 bpf/generictracer/protocol_http.h
#pragma once

// HTTP 方法检测: 检查缓冲区前几个字节
static __always_inline int detect_http_method(const unsigned char *buf, int len) {
    if (len < 4) return -1;
    // GET
    if (buf[0] == 'G' && buf[1] == 'E' && buf[2] == 'T' && buf[3] == ' ')
        return 0;
    // POST
    if (len >= 5 && buf[0] == 'P' && buf[1] == 'O' && buf[2] == 'S' && buf[3] == 'T')
        return 1;
    // PUT
    if (buf[0] == 'P' && buf[1] == 'U' && buf[2] == 'T' && buf[3] == ' ')
        return 2;
    // DELETE
    if (len >= 7 && buf[0] == 'D' && buf[1] == 'E' && buf[2] == 'L')
        return 3;
    return -1;
}

// HTTP 响应检测: "HTTP/1.x NNN"
static __always_inline int detect_http_response(const unsigned char *buf, int len) {
    if (len < 12) return -1;
    if (buf[0] == 'H' && buf[1] == 'T' && buf[2] == 'T' && buf[3] == 'P') {
        // 提取状态码: 位置 9-11
        int status = (buf[9] - '0') * 100 + (buf[10] - '0') * 10 + (buf[11] - '0');
        return status;
    }
    return -1;
}
/*
OBI 的 protocol_http.h 做了更复杂的事情:
  - 支持 HTTP/1.0 和 HTTP/1.1
  - 提取完整的请求路径
  - 提取 Content-Type
  - 处理 chunked encoding
  - 关联请求和响应
*/
