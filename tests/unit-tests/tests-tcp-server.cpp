#include "tests-common.h"

#define TEST_TCP_PORT	0 // 0 - any port
#define TEST_TCP_ADDR	"127.0.0.1"

TEST(cpp_lite_sockets__tcp_server, test1) {
    using namespace cpp_lite_sockets;
    sockaddr_wrap addr_server;
    errorcode_t ec = 0;
    ec = addr_server.set_ipv4_port(TEST_TCP_PORT).set_ipv4_addr(TEST_TCP_ADDR);
    ASSERT_EQ(ec, 0);
    ASSERT_TRUE(addr_server.get_port() == TEST_TCP_PORT);

    // Test data size should be greater than send/receive buffer otherwise 
    // local connect and send operation will complete before tcp server accepts the local connection
    const size_t test_data_size = 1024 * 128; 
    std::vector<char> buff_data(test_data_size, 0);
    buff_t allocated_buff(buff_data);
    buff_t recv_buff = {};

    auto client_handler = [&recv_buff, allocated_buff](socket_t client, const sockaddr_wrap& client_addr) {
        errorcode_t ec;
        std::tie(recv_buff, ec) = socket_recv_all(client, allocated_buff);
        ASSERT_EQ(ec, 0);
    };
    server_t server;
    std::tie(server, ec) = tcpserver_create(addr_server, client_handler);
    ASSERT_EQ(ec, 0);
    ASSERT_TRUE(!!server);
    ASSERT_TRUE((server->get_server_addr().get_port() == TEST_TCP_PORT) || (TEST_TCP_PORT == 0));

    socket_t sock_client;
    std::tie(sock_client, ec) = socket_create_tcp(AF_INET);
    ASSERT_EQ(ec, 0);
    ASSERT_TRUE(!!sock_client);

    std::vector<char> data_to_send(test_data_size, 0);
    for (size_t i = 0; i < data_to_send.size(); ++i) {
        data_to_send[i] = static_cast<char>(i & 0xFF);
    }

    ec = socket_connect(sock_client, server->get_server_addr());
    ASSERT_TRUE(ec == 0);

    ec = socket_send_all(sock_client, buff_t(data_to_send));
    ASSERT_TRUE(ec == 0);

    server.reset();
    
    ASSERT_TRUE(recv_buff.len == data_to_send.size() && 
        0 == std::memcmp(recv_buff.data, data_to_send.data(), recv_buff.len));
}
