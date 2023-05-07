#include "tests-common.h"

TEST(cpp_lite_sockets__sockaddr_wrap, test_init_zero) {
    using namespace cpp_lite_sockets;
    sockaddr_wrap sa;
    EXPECT_EQ(sa.get_len(), 0);
    EXPECT_EQ(sa.get_family(), 0);
    EXPECT_EQ(sa.to_string(), "unspecified");
    char zero_bytes[sizeof(sa.sa)] = {};
    EXPECT_TRUE(std::memcmp(&sa.sa, zero_bytes, sizeof(zero_bytes)) == 0);
}

TEST(cpp_lite_sockets__sockaddr_wrap, test_addr_loopback_ipv4) {
    using namespace cpp_lite_sockets;
    sockaddr_wrap sa;
    sa.set_ipv4_addr(INADDR_LOOPBACK);
    EXPECT_EQ(sa.get_len(), sizeof(sockaddr_in));
    EXPECT_TRUE(sa.is_local_addr());
    EXPECT_EQ(sa.get_port(), 0);

    sa.set_ipv4_port(1234);
    EXPECT_EQ(sa.get_len(), sizeof(sockaddr_in));
    EXPECT_TRUE(sa.is_local_addr());
    EXPECT_EQ(sa.get_port(), 1234);
    EXPECT_EQ(sa.to_string(), "127.0.0.1:1234");
    EXPECT_EQ(sa.to_string(false), "127.0.0.1");

    sockaddr_wrap sa2;
    sa2.set_ipv4_port(2345);
    EXPECT_EQ(sa2.get_len(), sizeof(sockaddr_in));
    EXPECT_TRUE(!sa2.is_local_addr());
    EXPECT_EQ(sa2.get_port(), 2345);
    EXPECT_EQ(sa2.to_string(), "0.0.0.0:2345");
}

TEST(cpp_lite_sockets__sockaddr_wrap, test_addr_loopback_ipv6) {
    using namespace cpp_lite_sockets;
    sockaddr_wrap sa;
    sa.set_ipv6_addr(in6_addr(IN6ADDR_LOOPBACK_INIT));
    EXPECT_EQ(sa.get_len(), sizeof(sockaddr_in6));
    EXPECT_TRUE(sa.is_local_addr());
    EXPECT_EQ(sa.get_port(), 0);

    sa.set_ipv6_port(1234);
    EXPECT_EQ(sa.get_len(), sizeof(sockaddr_in6));
    EXPECT_TRUE(sa.is_local_addr());
    EXPECT_EQ(sa.get_port(), 1234);
    EXPECT_EQ(sa.to_string(), "::1:1234");
    EXPECT_EQ(sa.to_string(false), "::1");
    sa.set_ipv6_scope(36);
    EXPECT_EQ(sa.to_string(), "::1%36:1234");
    EXPECT_EQ(sa.to_string(false), "::1%36");
    EXPECT_EQ(sa.to_string(false, false), "::1");

    sockaddr_wrap sa2;
    sa2.set_ipv6_port(2345);
    EXPECT_EQ(sa2.get_len(), sizeof(sockaddr_in6));
    EXPECT_TRUE(!sa2.is_local_addr());
    EXPECT_EQ(sa2.get_port(), 2345);
    EXPECT_EQ(sa2.to_string(), ":::2345");
}

TEST(cpp_lite_sockets__sockaddr_wrap, test_addr_v4_resolve) {
    using namespace cpp_lite_sockets;
    sockaddr_wrap sa;
    EXPECT_EQ(sa.resolve_ipv4_addr("127.0.0.1"), 0);
    EXPECT_TRUE(sa.is_local_addr());
    EXPECT_EQ(sa.to_string(), "127.0.0.1");
}

TEST(cpp_lite_sockets__sockaddr_wrap, test_addr_v4_resolve_bad) {
    using namespace cpp_lite_sockets;
    sockaddr_wrap sa;
    EXPECT_NE(sa.resolve_ipv4_addr("127.0.0.1.2"), 0);
    EXPECT_NE(sa.resolve_ipv4_addr("127::1"), 0);
}

TEST(cpp_lite_sockets__sockaddr_wrap, test_addr_v6_resolve) {
    using namespace cpp_lite_sockets;
    sockaddr_wrap sa;
    EXPECT_EQ(sa.resolve_ipv6_addr("::1"), 0);
    EXPECT_TRUE(sa.is_local_addr());
    EXPECT_EQ(sa.to_string(), "::1");
}

TEST(cpp_lite_sockets__sockaddr_wrap, test_addr_v6_resolve_bad) {
    using namespace cpp_lite_sockets;
    sockaddr_wrap sa;
    EXPECT_NE(sa.resolve_ipv6_addr("1:2:3:4:5:6:7"), 0);
}
