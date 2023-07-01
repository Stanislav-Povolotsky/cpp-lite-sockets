#include "tests-common.h"
#include <algorithm>
#include <chrono>
#include <thread>
#include <mutex>
#include <condition_variable>

#define TEST_UDP_PORT	0 // 0 - any port
#define TEST_UDP_ADDR	"127.0.0.1"

TEST(cpp_lite_sockets__udp_server, simple_udp_server1) {
    using namespace cpp_lite_sockets;
    sockaddr_wrap addr_server;
    errorcode_t ec = 0;
    ec = addr_server.set_ipv4_port(TEST_UDP_PORT).set_ipv4_addr(TEST_UDP_ADDR);
    ASSERT_EQ(ec, 0);
    ASSERT_TRUE(addr_server.get_port() == TEST_UDP_PORT);

    const size_t test_data_size = 32 * 128;
    std::vector<char> buff_data(test_data_size, 0);
    buff_t allocated_buff(buff_data);
    buff_t recv_buff = {};
    volatile bool received = false;
    std::condition_variable cv;
    std::mutex cv_m;

    auto client_handler = [&received, &cv, &cv_m, &recv_buff, allocated_buff](socket_t server_socket, const buff_t& datagram, const sockaddr_wrap& client_addr) {
        recv_buff.data = allocated_buff.data;
        recv_buff.len = std::min(datagram.len, allocated_buff.len);
        std::memcpy(allocated_buff.data, datagram.data, recv_buff.len);
        cv.notify_all();
        std::lock_guard<std::mutex> lk(cv_m);
        received = true;
    };
    server_t server;
    std::tie(server, ec) = udpserver_create(addr_server, client_handler);
    ASSERT_EQ(ec, 0);
    ASSERT_TRUE(!!server);
    ASSERT_TRUE((server->get_server_addr().get_port() == TEST_UDP_PORT) || (TEST_UDP_PORT == 0));

    socket_t sock_client;
    std::tie(sock_client, ec) = socket_create_udp(AF_INET);
    ASSERT_EQ(ec, 0);
    ASSERT_TRUE(!!sock_client);

    std::vector<char> data_to_send(test_data_size, 0);
    for (size_t i = 0; i < data_to_send.size(); ++i) {
        data_to_send[i] = static_cast<char>(i & 0xFF);
    }

    size_t sent_n = 0;
    std::tie(sent_n, ec) = socket_send_to(sock_client, buff_t(data_to_send), server->get_server_addr());
    ASSERT_EQ(ec, 0);
    ASSERT_TRUE(sent_n == data_to_send.size());

    std::unique_lock<std::mutex> lk(cv_m);
    cv.wait_for(lk, std::chrono::milliseconds(500), [&received] {return received; });
    ASSERT_TRUE(received);

    server.reset();
    
    ASSERT_TRUE(recv_buff.len == data_to_send.size() && 
        0 == std::memcmp(recv_buff.data, data_to_send.data(), recv_buff.len));
}
