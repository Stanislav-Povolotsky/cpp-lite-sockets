#include "tests-common.h"

TEST(cpp_lite_sockets__socket_create, socket_create_tcp__ipv4) {
    using namespace cpp_lite_sockets;
    errorcode_t ec;
    socket_t socket;
    std::tie(socket, ec) = socket_create_tcp(AF_INET);
    EXPECT_TRUE(ec == 0 && socket && *socket);
}

TEST(cpp_lite_sockets__socket_create, socket_create_tcp__ipv6) {
    using namespace cpp_lite_sockets;
    errorcode_t ec;
    socket_t socket;
    std::tie(socket, ec) = socket_create_tcp(AF_INET6);
    EXPECT_TRUE(ec == 0 && socket && *socket);
}

TEST(cpp_lite_sockets__socket_create, socket_create_tcp__invalid_af) {
    using namespace cpp_lite_sockets;
    errorcode_t ec;
    socket_t socket;
    std::tie(socket, ec) = socket_create_tcp(253); // 253 - invalid address family
    EXPECT_TRUE(ec != 0 && !socket);
    auto s_error = get_error_str(ec);
    EXPECT_TRUE(!s_error.empty());
}

TEST(cpp_lite_sockets__socket_create, socket_create_tcp__two_sockets_are_different) {
    using namespace cpp_lite_sockets;
    errorcode_t ec;
    socket_t socket1, socket2;
    std::tie(socket1, ec) = socket_create_tcp();
    EXPECT_TRUE(ec == 0);
    std::tie(socket2, ec) = socket_create_tcp();
    EXPECT_TRUE(ec == 0);
    EXPECT_TRUE(*socket1 != *socket2);
}

TEST(cpp_lite_sockets__socket_create, socket_create_udp__ipv4) {
    using namespace cpp_lite_sockets;
    errorcode_t ec;
    socket_t socket;
    std::tie(socket, ec) = socket_create_udp(AF_INET);
    EXPECT_TRUE(ec == 0 && socket && *socket);
}

TEST(cpp_lite_sockets__socket_create, socket_create_udp__ipv6) {
    using namespace cpp_lite_sockets;
    errorcode_t ec;
    socket_t socket;
    std::tie(socket, ec) = socket_create_udp(AF_INET6);
    EXPECT_TRUE(ec == 0 && socket && *socket);
}

TEST(cpp_lite_sockets__socket_create, socket_create_udp__invalid_af) {
    using namespace cpp_lite_sockets;
    errorcode_t ec;
    socket_t socket;
    std::tie(socket, ec) = socket_create_udp(253); // 253 - invalid address family
    EXPECT_TRUE(ec != 0 && !socket);
    auto s_error = get_error_str(ec);
    EXPECT_TRUE(!s_error.empty());
}

TEST(cpp_lite_sockets__socket_create, socket_create__manual_udp4) {
    using namespace cpp_lite_sockets;
    errorcode_t ec;
    socket_t socket;
    std::tie(socket, ec) = socket_create(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    EXPECT_TRUE(ec == 0 && *socket);
}

TEST(cpp_lite_sockets__socket_create, socket_create__manual_udp6_invalid_type) {
    using namespace cpp_lite_sockets;
    errorcode_t ec;
    socket_t socket;
    // SOCK_STREAM type is invalid for protocol IPPROTO_UDP
    std::tie(socket, ec) = socket_create(AF_INET6, SOCK_STREAM, IPPROTO_UDP);
    EXPECT_TRUE(ec != 0 && !socket);
}

TEST(cpp_lite_sockets__socket_create, socket_create__manual_tcp6) {
    using namespace cpp_lite_sockets;
    errorcode_t ec;
    socket_t socket;
    std::tie(socket, ec) = socket_create(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    EXPECT_TRUE(ec == 0 && *socket);
}

TEST(cpp_lite_sockets__socket_create, socket_create__manual_tcp4_invalid_type) {
    using namespace cpp_lite_sockets;
    errorcode_t ec;
    socket_t socket;
    // SOCK_DGRAM type is invalid for protocol IPPROTO_TCP
    std::tie(socket, ec) = socket_create(AF_INET, SOCK_DGRAM, IPPROTO_TCP);
    EXPECT_TRUE(ec != 0 && !socket);
}

TEST(cpp_lite_sockets__socket_duplicate_and_close, test) {
    using namespace cpp_lite_sockets;
    errorcode_t ec;
    socket_t socket1, socket2;

    std::tie(socket1, ec) = socket_create_tcp(AF_INET6);
    EXPECT_TRUE(ec == 0 && *socket1);

    socket2 = socket1;
    EXPECT_TRUE(socket1.get() == socket2.get());
    EXPECT_TRUE(*socket1 == *socket2);

    socket_close(socket1);
    EXPECT_TRUE(!socket1 && socket2);

    int sock_type = 0;
    ec = socket_getopt(socket2, SOL_SOCKET, SO_TYPE, sock_type);
    EXPECT_EQ(ec, 0);
    EXPECT_EQ(sock_type, SOCK_STREAM);

    sock_type = 0;
    ec = socket_getopt(socket1, SOL_SOCKET, SO_TYPE, sock_type);
    EXPECT_NE(ec, 0);
    EXPECT_NE(sock_type, SOCK_STREAM);
}
