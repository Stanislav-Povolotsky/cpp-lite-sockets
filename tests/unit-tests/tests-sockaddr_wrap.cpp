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
    EXPECT_EQ(sa.set_ipv4_addr("127.0.0.1"), 0);
    EXPECT_TRUE(sa.is_local_addr());
    EXPECT_EQ(sa.to_string(), "127.0.0.1");
}

TEST(cpp_lite_sockets__sockaddr_wrap, test_addr_v4_resolve_bad) {
    using namespace cpp_lite_sockets;
    sockaddr_wrap sa;
    EXPECT_NE(sa.set_ipv4_addr("127.0.0.1.2"), 0);
    EXPECT_NE(sa.set_ipv4_addr("127::1"), 0);
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

TEST(cpp_lite_sockets__sockaddr_wrap, test_addr_auto_resolve) {
    using namespace cpp_lite_sockets;
    sockaddr_wrap sa1;
    ASSERT_EQ(sa1.set_ip_addr("::1", 234), 0);
    EXPECT_EQ(sa1.to_string(), "::1:234");
    EXPECT_EQ(sa1.get_family(), AF_INET6);
    sockaddr_wrap sa2;
    ASSERT_EQ(sa2.set_ip_addr("127.0.0.1", 345), 0);
    EXPECT_EQ(sa2.to_string(), "127.0.0.1:345");
    EXPECT_EQ(sa2.get_family(), AF_INET);
}

TEST(cpp_lite_sockets__sockaddr_wrap, test_ip_or_name_resolve) {
    using namespace cpp_lite_sockets;
    sockaddr_wrap sa;
    ASSERT_EQ(sa.resolve("::1", "60222"), 0);
    EXPECT_EQ(sa.to_string(), "::1:60222");
    EXPECT_EQ(sa.get_family(), AF_INET6);

    ASSERT_EQ(sa.resolve("ab:0::1"), 0);
    EXPECT_EQ(sa.to_string(), "ab::1");

    ASSERT_EQ(sa.resolve("127.0.0.1", "235"), 0);
    EXPECT_EQ(sa.to_string(), "127.0.0.1:235");
    EXPECT_EQ(sa.get_family(), AF_INET);

    ASSERT_EQ(sa.resolve("120.250.0.99", "ssh"), 0);
    EXPECT_EQ(sa.to_string(), "120.250.0.99:22");
    EXPECT_EQ(sa.get_family(), AF_INET);

    ASSERT_EQ(sa.resolve("localhost"), 0);
    EXPECT_TRUE((sa.to_string() == "127.0.0.1" && sa.get_family() == AF_INET) || 
        (sa.to_string() == "::1" && sa.get_family() == AF_INET6));

    ASSERT_EQ(sa.resolve("localhost", "235", AF_INET), 0);
    EXPECT_EQ(sa.to_string(), "127.0.0.1:235");
    EXPECT_EQ(sa.get_family(), AF_INET);

    ASSERT_EQ(sa.resolve("localhost", "235", AF_INET6), 0);
    EXPECT_EQ(sa.to_string(), "::1:235");
    EXPECT_EQ(sa.get_family(), AF_INET6);
}

TEST(cpp_lite_sockets__sockaddr_wrap, test_ip_or_name_resolve__bad) {
    using namespace cpp_lite_sockets;
    sockaddr_wrap sa;
    ASSERT_NE(sa.resolve("::1", "some_unknown_service"), 0);
    ASSERT_NE(sa.resolve("::1", NULL, 253), 0); // Unknown address family

    // Invalid IPv6 addresses
    ASSERT_NE(sa.resolve("x::1"), 0); 
    ASSERT_NE(sa.resolve("1::2::1"), 0);
    ASSERT_NE(sa.resolve("1:2:3:4:5:6:7"), 0);

    // Invalid IPv4 addresses
    ASSERT_NE(sa.resolve("1.2.3.4.5"), 0);
    ASSERT_NE(sa.resolve("1..4"), 0);

    // Invalid host names
    ASSERT_NE(sa.resolve("ab..z"), 0);
    ASSERT_NE(sa.resolve("x@y.com"), 0);
    ASSERT_NE(sa.resolve(NULL), 0);
    ASSERT_NE(sa.resolve(""), 0);
}
