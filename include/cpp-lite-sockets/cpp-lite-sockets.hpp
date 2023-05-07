// MIT License
// 
// Copyright (C) 2023, Stanislav Povolotsky (stas.dev[at]povolotsky.info)
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// ------------------------------------------------------------------------------
// cpp-lite-sockets - C++11 sockets library
// - cross-platform
// - lightweight
// - single-header-file-only
// - exceptionless error-handling
// ------------------------------------------------------------------------------

#ifndef __CPP_LITE_SOCKETS__INCLUDED__
#define __CPP_LITE_SOCKETS__INCLUDED__

#if !defined(__cplusplus) || (defined(_MSC_VER) && (_MSC_VER < 1800)) || (!defined(_MSC_VER) && (__cplusplus < 201103L))
#error Minimal required version is C++11
#endif

//////////////////////////////////////////////////////////////////////////
// Includes
#ifdef _WIN32
// Windows includes
#if defined(_WINDOWS_) && !defined(_WINSOCK2API_)
#error Please, include 'winsock2.h' before 'windows.h'
#endif
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib,"ws2_32.lib")
#undef max // MS makes std::numeric_limits<T>::max() unusable without this line
#define CPP_LITE_SOCKETS_FN __declspec(noinline) inline
#else // !_WIN32
// Linux includes
typedef int SOCKET;
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
static const int INVALID_SOCKET = -1;
static const int SOCKET_ERROR = -1;
// ToDO:
//#define CPP_LITE_SOCKETS_FN [[gnu::noinline]] inline  
//#define CPP_LITE_SOCKETS_FN __attribute__((__noinline__)) inline
#define CPP_LITE_SOCKETS_FN inline
#endif
// Common includes
#include <memory>
#include <functional>
#include <thread>
#include <tuple>
#include <cstdint>
#include <string>
#include <cstring>
#include <atomic>
#include <limits>
#include <vector>
#include <array>
//////////////////////////////////////////////////////////////////////////

// Define your own logger to log an errors
// Logger example:
// #define CPP_LITE_SOCKETS__LOGGER(msg, ...) printf(msg "\n", __VA_ARGS__)
#ifndef CPP_LITE_SOCKETS__LOGGER
#define CPP_LITE_SOCKETS__LOGGER(...) // Logging is turned off by default
#endif

// You can define your own errorcode_t for 'connection gracefully closed' situation or even set it to 0 (no error)
#ifndef ECLS_CONNGRACEFULLYCLOSED
#define ECLS_CONNGRACEFULLYCLOSED   ((errorcode_t)0x80090001)
#endif 
// You can define your own errorcode_t for 'invalid socket' error
#ifndef ECLS_INVALIDSOCKET
#define ECLS_INVALIDSOCKET          ((errorcode_t)0x80090002)
#endif 

// Compatibility definitions for windows
#if defined(_WIN32) && !defined(SHUT_RDWR)
#define SHUT_RD     SD_RECEIVE
#define SHUT_WR     SD_SEND
#define SHUT_RDWR   SD_BOTH
#endif

// Compatibility for C++11 (std::make_unique is missing in C++11)
#if (!defined(_MSC_VER) && (__cplusplus < 201402L)) || (defined(_MSC_VER) && (_MSC_VER < 1800))
#define STD_MAKE_UNIQUE(T, ...) std::unique_ptr<T>(new T(__VA_ARGS__))
#else
#define STD_MAKE_UNIQUE(T, ...) std::make_unique<T>(__VA_ARGS__)
#endif

namespace cpp_lite_sockets
{
    // Types
    typedef int errorcode_t;                                // error code
    typedef std::shared_ptr<SOCKET> socket_t;               // SOCKET wrapper
    class sockaddr_wrap;                                    // sockaddr wrapper
    struct buff_t;                                          // buffer to send/receive the data
    class simple_server_itf;                                // simple tcp/udp server interface
    typedef std::shared_ptr< simple_server_itf > server_t;  // simple tcp/udp server smart pointer

    // Optional function to initialize windows sockets (can be called manually or will be called automatically)
    CPP_LITE_SOCKETS_FN errorcode_t sockets_initialize();
    // Optional function to cleanup windows sockets (can be never called, but it's recommended by MS to call this 
    // function when the app has completed the use of Windows Sockets)
    CPP_LITE_SOCKETS_FN void sockets_cleanup();

    // Get error description string
    CPP_LITE_SOCKETS_FN std::string get_error_str(errorcode_t ec);

    // Create new socket
    CPP_LITE_SOCKETS_FN std::pair<socket_t, errorcode_t> socket_create(int af /* = AF_INET6 */, int type /* = SOCK_STREAM | SOCK_DGRAM */, int protocol /* = IPPROTO_TCP*/);
    CPP_LITE_SOCKETS_FN std::pair<socket_t, errorcode_t> socket_create_tcp(int af = AF_INET6);
    CPP_LITE_SOCKETS_FN std::pair<socket_t, errorcode_t> socket_create_udp(int af = AF_INET6);

    // Close the socket
    CPP_LITE_SOCKETS_FN void socket_close(socket_t& socket);
    CPP_LITE_SOCKETS_FN void socket_close(SOCKET socket);

    // Create socket_t from SOCKET
    CPP_LITE_SOCKETS_FN socket_t socket_wrap(SOCKET socket);

    // Connect 
    CPP_LITE_SOCKETS_FN errorcode_t socket_connect(const socket_t& socket, const sockaddr_wrap& sa);

    // Send buffer (actually send function can send less then buff.len) 
    CPP_LITE_SOCKETS_FN std::pair<size_t, errorcode_t> socket_send(const socket_t& socket, const buff_t& buff, int flags = 0);
    // Send the whole buffer
    CPP_LITE_SOCKETS_FN errorcode_t socket_send_all(const socket_t& socket, const buff_t& buff, int flags = 0);

    // Receive (recv)
    // Returns:
    // - non-empty data buffer, if there was no error
    // - error ECLS_CONNGRACEFULLYCLOSED when there is no data to received, because the connection has been gracefully closed.
    CPP_LITE_SOCKETS_FN std::pair<buff_t, errorcode_t> socket_recv(const socket_t& socket, const buff_t& buff, int flags = 0);
    // Receive the whole buffer
    // Returns:
    // - filled data buffer, if there was no error
    // - error code if there was any error
    CPP_LITE_SOCKETS_FN std::pair<buff_t, errorcode_t> socket_recv_all(const socket_t& socket, const buff_t& buff, int flags = 0);

    // Receive datagram (recvfrom wrapper)
    CPP_LITE_SOCKETS_FN std::tuple<buff_t, sockaddr_wrap, errorcode_t> socket_recv_from(const socket_t& socket, const buff_t& buff, int flags = 0);

    // Send datagram (sendto wrapper)
    CPP_LITE_SOCKETS_FN std::pair<size_t, errorcode_t> socket_send_to(const socket_t& socket, const buff_t& buff, const sockaddr_wrap& to_addr, int flags = 0);

    // Bind socket
    CPP_LITE_SOCKETS_FN errorcode_t socket_bind(const socket_t& socket, const sockaddr_wrap& sa);

    // Bind listen
    CPP_LITE_SOCKETS_FN errorcode_t socket_listen(const socket_t& socket, int backlog = SOMAXCONN);

    // Accept connection
    CPP_LITE_SOCKETS_FN std::tuple<socket_t, sockaddr_wrap, errorcode_t> socket_accept(const socket_t& server_socket);

    // Shutdown socket
    // If `how` is 
    // - SHUT_RD, further receptions will be disallowed
    // - SHUT_WR, further transmissions will be disallowed
    // - SHUT_RDWR, further receptions and transmissions will be disallowed
    CPP_LITE_SOCKETS_FN errorcode_t socket_shutdown(const socket_t& socket, int how = SHUT_RDWR);

    // getsockopt
    CPP_LITE_SOCKETS_FN errorcode_t socket_getopt(const socket_t& socket, int level, int optname, void* optval, int optlen);
    template<class T>
    CPP_LITE_SOCKETS_FN errorcode_t socket_getopt(const socket_t& socket, int level, int optname, T& optval);

    // setsockopt
    CPP_LITE_SOCKETS_FN errorcode_t socket_setopt(const socket_t& socket, int level, int optname, const char* optval, int optlen);
    template<class T>
    CPP_LITE_SOCKETS_FN errorcode_t socket_setopt(const socket_t& socket, int level, int optname, const T& optval);
    
    // setsockopt IPPROTO_IPV6 / IPV6_V6ONLY
    // some platforms turns on dualstack mode by default
    CPP_LITE_SOCKETS_FN errorcode_t socket_setopt_dualstack(const socket_t& socket, bool dualstack = true);

    // getsockname (get local socket address)
    CPP_LITE_SOCKETS_FN std::pair<sockaddr_wrap, errorcode_t> socket_getsockname(const socket_t& socket);

    // getpeername (get remote peer address)
    CPP_LITE_SOCKETS_FN std::pair<sockaddr_wrap, errorcode_t> socket_getpeername(const socket_t& socket);

    //////////////////////////////////////////////////////////////////////////
    // TCP / UDP servers

    // TCP Server
    // To shutdown the server just release the server_t smart pointer
    CPP_LITE_SOCKETS_FN std::pair<server_t, errorcode_t> tcpserver_create(const sockaddr_wrap& server_addr,
        std::function<void(socket_t client_socket, const sockaddr_wrap& client_addr)> fn_on_new_client,
        std::function<errorcode_t(socket_t server_socket)> fn_on_prepare_server_socket = std::function<errorcode_t(socket_t server_socket)>());

    // UDP Server
    CPP_LITE_SOCKETS_FN std::pair<server_t, errorcode_t> udpserver_create(const sockaddr_wrap& server_addr,
        std::function<void(socket_t server_socket, const buff_t& datagram, const sockaddr_wrap& client_addr)> fn_on_data,
        std::function<errorcode_t(socket_t server_socket)> fn_on_prepare_server_socket = std::function<errorcode_t(socket_t server_socket)>());
}

//////////////////////////////////////////////////////////////////////////
// simple_server_itf, sockaddr & buffer wrappers

namespace cpp_lite_sockets
{
    namespace impl 
    {
        union sockaddr_max
        {
            sockaddr sa;
            sockaddr_in6 sa_in6;
            sockaddr_in sa_in4;
        };
        inline errorcode_t check_socket_error(SOCKET res);
        inline errorcode_t check_int_error(int res);
    }

    // buffer to send/receive the data
    struct buff_t
    {
        void* data = nullptr;
        size_t len = 0;
        buff_t() {}
        buff_t(const void* data_, size_t len_) : data(const_cast<void*>(data_)), len(len_) {}
        template<class T>
        buff_t(const std::vector<T>& buff) : data(const_cast<T*>(buff.data())), len(buff.size()) {}
        template <typename T, size_t size>
        buff_t(const T(&array)[size]) : data(const_cast<T*>(array)), len(size) {}
        template <typename T, size_t size>
        buff_t(const std::array<T, size>& arr) : data(const_cast<T*>(arr.data())), len(arr.size()) {}
    };

    class sockaddr_wrap
    {
    public:
        impl::sockaddr_max sa = {};
        int len = 0;
    public:
        sockaddr_wrap() { };
        sockaddr_wrap(const sockaddr& sa_, int sa_len) : len(sa_len) { std::memcpy(&sa, &sa_, sa_len); };
        int get_len() const { return len; }
        operator const sockaddr* () const { return &sa.sa; }
        operator sockaddr* () { return &sa.sa; }
        int get_family() const { return sa.sa.sa_family; }
        CPP_LITE_SOCKETS_FN std::uint16_t get_port() const;
        CPP_LITE_SOCKETS_FN std::string to_string(bool with_port = true, bool with_scope_id = true) const;

        CPP_LITE_SOCKETS_FN bool is_any_addr() const;
        CPP_LITE_SOCKETS_FN bool is_local_addr() const;

    public:
        // IPv4
        sockaddr_wrap& set_ipv4() {
            len = sizeof(sockaddr_in);
            sa.sa.sa_family = AF_INET;
            return *this;
        }
        sockaddr_wrap& set_ipv4_port(std::uint16_t port) {
            set_ipv4();
            sa.sa_in4.sin_port = htons(port);
            return *this;
        }
        sockaddr_wrap& set_ipv4_addr(std::uint32_t addr = INADDR_ANY) {
            set_ipv4();
            sa.sa_in4.sin_addr.s_addr = htonl(addr);
            return *this;
        }
        errorcode_t resolve_ipv4_addr(const char* addr) {
            errorcode_t res = 0;
            set_ipv4();
            int ret = ::inet_pton(AF_INET, addr, &sa.sa_in4.sin_addr);
            res = impl::check_socket_error(ret);
            if (ret == 0) {
                res = EADDRNOTAVAIL;
            }
            if (res) {
                CPP_LITE_SOCKETS__LOGGER("Error resolving network ipv4 address '%s': %d", addr, res);
            }
            return res;
        }

        // IPv6
        sockaddr_wrap& set_ipv6() {
            len = sizeof(sockaddr_in6);
            sa.sa.sa_family = AF_INET6;
            return *this;
        }
        sockaddr_wrap& set_ipv6_port(std::uint16_t port) {
            set_ipv6();
            sa.sa_in6.sin6_port = htons(port);
            return *this;
        }
        sockaddr_wrap& set_ipv6_addr(const in6_addr& addr = in6_addr(IN6ADDR_ANY_INIT)) {
            set_ipv6();
            sa.sa_in6.sin6_addr = addr;
            return *this;
        }
        sockaddr_wrap& set_ipv6_scope(std::uint32_t scope) {
            set_ipv6();
            sa.sa_in6.sin6_scope_id = scope;
            return *this;
        }
        std::uint32_t get_ipv6_scope() const {
            return sa.sa_in6.sin6_scope_id;
        }
        errorcode_t resolve_ipv6_addr(const char* addr) {
            errorcode_t res = 0;
            set_ipv6();
            int ret = ::inet_pton(AF_INET6, addr, &sa.sa_in6.sin6_addr);
            res = impl::check_int_error(ret);
            if (ret == 0) {
                res = EADDRNOTAVAIL;
            }
            if (res) {
                CPP_LITE_SOCKETS__LOGGER("Error resolving network ipv6 address '%s': %d", addr, res);
            }
            return res;
        }
    };

    class simple_server_itf
    {
    public:
        virtual ~simple_server_itf() {};
        virtual void shutdown() = 0;
        virtual socket_t get_server_socket() = 0;
        virtual const sockaddr_wrap& get_server_addr() = 0;
    };
}

//////////////////////////////////////////////////////////////////////////
// Implementation

namespace cpp_lite_sockets
{
#ifdef _WIN32 // Windows implementation
    namespace impl
    {
        CPP_LITE_SOCKETS_FN std::atomic<int>& initialization_counter()
        {
            static std::atomic<int> s_val{};
            return s_val;
        }
        CPP_LITE_SOCKETS_FN errorcode_t sockets_initialize()
        {
            WSADATA wsaData;
            errorcode_t res = ::WSAStartup(MAKEWORD(2, 2), &wsaData);
            if (res != 0) {
                CPP_LITE_SOCKETS__LOGGER("WinSock initialization error: %d", res);
            }
            return res;
        }
        inline errorcode_t get_last_error()
        {
            return ::WSAGetLastError();
        }
        CPP_LITE_SOCKETS_FN std::string get_error_str(errorcode_t ec)
        {
            std::string res;
            char* s = NULL;
            if (!::FormatMessageA(
                FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                NULL, static_cast<DWORD>(ec),
                MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                (LPSTR)&s, 0, NULL))
            {
                s = NULL;
            }
            if (s)
            {
                auto s_end = s;
                // Cut off the newline
                while (*s_end != 0 && *s_end != '\r' && *s_end != '\n') {
                    ++s_end;
                }
                // Cut off the last point.
                if (s_end != s && *(s_end - 1) == '.') {
                    --s_end;
                }
                res = std::string(s, s_end - s);
                ::LocalFree(s);
            }
            
            if(res.empty()) {
                res = std::string("Unknown error: ") + std::to_string(static_cast<int>(ec));
            }
            return res;
        }
        inline errorcode_t check_socket_error(SOCKET res)
        {
            return (res == SOCKET_ERROR) ? ::WSAGetLastError() : 0;
        }
        inline errorcode_t check_int_error(int res)
        {
            return (res == SOCKET_ERROR) ? ::WSAGetLastError() : 0;
        }
    }

    CPP_LITE_SOCKETS_FN errorcode_t sockets_initialize()
    {
        errorcode_t res = 0;
        auto& init_counter = impl::initialization_counter();
        if (init_counter.load() == 0)
        {
            res = impl::sockets_initialize();
            if (res == 0) {
                init_counter++;
            }
        }
        return res;
    }

    CPP_LITE_SOCKETS_FN void sockets_cleanup()
    {
        auto& init_counter = impl::initialization_counter();
        do
        {
            int prev_value = init_counter.load();
            if (prev_value <= 0) {
                break;
            }
            if(!init_counter.compare_exchange_strong(prev_value, prev_value - 1, std::memory_order_relaxed)) {
                continue;
            }
            // WSACleanup should be called the same times like WSAStartup was called
            ::WSACleanup();
        } while (true);
    }

    CPP_LITE_SOCKETS_FN void socket_close(SOCKET socket)
    {
        ::closesocket(socket);
    }

#else // non-windows implementation
    namespace impl
    {
        inline errorcode_t get_last_error()
        {
            return errno;
        }
        inline std::string get_error_str(errorcode_t ec)
        {
            auto res = std::strerror(ec);
            return res ? res : (std::string("Unknown error: ") + std::to_string(static_cast<int>(ec)));
        }
        inline errorcode_t check_socket_error(SOCKET res)
        {
            return (res < 0) ? errno : 0;
        }
        inline errorcode_t check_int_error(int res)
        {
            return (res < 0) ? errno : 0;
        }
    }

    CPP_LITE_SOCKETS_FN errorcode_t sockets_initialize()
    {
        return 0;
    }
    CPP_LITE_SOCKETS_FN void sockets_cleanup()
    {
    }
    CPP_LITE_SOCKETS_FN void socket_close(SOCKET socket)
    {
        ::close(socket);
    }
#endif 
    namespace impl
    {
        inline errorcode_t check_socket_valid(const socket_t& socket)
        {
            return socket ? 0 : EINVAL;
        }
    }

    CPP_LITE_SOCKETS_FN std::string get_error_str(errorcode_t ec)
    {
        if (ec)
        {
            switch (ec)
            {
            case ECLS_CONNGRACEFULLYCLOSED:
                return "The connection was gracefully closed";
            case ECLS_INVALIDSOCKET:
                return "Invalid socket";
            }
        }
        return impl::get_error_str(ec);
    }


    CPP_LITE_SOCKETS_FN void socket_close(socket_t& socket)
    {
        socket.reset();
    }

    CPP_LITE_SOCKETS_FN socket_t socket_wrap(SOCKET socket)
    {
        socket_t res;
        if(socket != INVALID_SOCKET) {
            res = socket_t(new SOCKET(socket), [](SOCKET* p_socket) {
                SOCKET s = *p_socket;
                *p_socket = INVALID_SOCKET;
                socket_close(s);
                delete p_socket;
            });
        }
        return res;
    }

    CPP_LITE_SOCKETS_FN std::pair<socket_t, errorcode_t> socket_create(int af /* = AF_INET */, int type /* = SOCK_STREAM | SOCK_DGRAM */, int protocol /* = IPPROTO_TCP*/)
    {
        sockets_initialize();
        std::pair<socket_t, errorcode_t> res;
        auto& ec = res.second;
        SOCKET socket = ::socket(af, type, protocol);
        ec = impl::check_socket_error(socket);
        if (ec == 0) {
            res.first = socket_wrap(socket);
        }
        else {
            CPP_LITE_SOCKETS__LOGGER("Error creating new socket(af = %d, type = %d, protocol = %d): %d", af, type, protocol, ec);
        }
        return res;
    }

    CPP_LITE_SOCKETS_FN std::pair<socket_t, errorcode_t> socket_create_tcp(int af /*= AF_INET6*/)
    {
        return socket_create(af, SOCK_STREAM, IPPROTO_TCP);
    }

    CPP_LITE_SOCKETS_FN std::pair<socket_t, errorcode_t> socket_create_udp(int af /*= AF_INET6*/)
    {
        return socket_create(af, SOCK_DGRAM, IPPROTO_UDP);
    }

    CPP_LITE_SOCKETS_FN errorcode_t socket_connect(const socket_t& socket, const sockaddr_wrap& sa)
    {
        errorcode_t ec = impl::check_socket_valid(socket);
        if (ec == 0) {
            ec = impl::check_int_error(::connect(*socket, sa, sa.get_len()));
        }
        return ec;
    }

    CPP_LITE_SOCKETS_FN errorcode_t socket_bind(const socket_t& socket, const sockaddr_wrap& sa)
    {
        errorcode_t ec = impl::check_socket_valid(socket);
        if (ec == 0) {
            ec = impl::check_int_error(::bind(*socket, sa, sa.get_len()));
            if (ec != 0) {
                CPP_LITE_SOCKETS__LOGGER("Error binding socket to the address %s: %d", sa.to_string().c_str(), ec);
            }
        }
        return ec;
    }

    CPP_LITE_SOCKETS_FN errorcode_t socket_listen(const socket_t& socket, int backlog /* = SOMAXCONN */)
    {
        errorcode_t ec = impl::check_socket_valid(socket);
        if (ec == 0) {
            ec = impl::check_int_error(::listen(*socket, backlog));
            if (ec != 0) {
                CPP_LITE_SOCKETS__LOGGER("Error starting listening for the socket: %d", ec);
            }
        }
        return ec;
    }

    CPP_LITE_SOCKETS_FN std::tuple<socket_t, sockaddr_wrap, errorcode_t> socket_accept(const socket_t& server_socket)
    {
        std::tuple<socket_t, sockaddr_wrap, errorcode_t> res;
        auto& sock = std::get<0>(res);
        auto& sa = std::get<1>(res);
        auto& ec = std::get<2>(res);
        ec = impl::check_socket_valid(server_socket);
        if (ec == 0) 
        {
            socklen_t len = sizeof(sa.sa);
            auto client_socket = ::accept(*server_socket, &sa.sa.sa, &len);
            ec = impl::check_socket_error(client_socket);
            if (ec == 0) {
                sa.len = len;
                sock = socket_wrap(client_socket);
            }
        }
        return res;
    }

    CPP_LITE_SOCKETS_FN errorcode_t socket_shutdown(const socket_t& socket, int how /*= SHUT_RDWR*/)
    {
        errorcode_t ec = impl::check_socket_valid(socket);
        if (ec == 0) {
            ec = impl::check_int_error(::shutdown(*socket, how));
        }
        return ec;
    }

    //////////////////////////////////////////////////////////////////////////

    namespace impl 
    { 
#ifdef _WIN32
        inline errorcode_t turn_off_conn_reset_notifications_on_recv(const socket_t& socket)
        {
            #define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)

            errorcode_t ec = check_socket_valid(socket);
            if (ec == 0)
            {
                BOOL bNewBehavior = FALSE;
                DWORD dwBytesReturned = 0;
                auto ret = ::WSAIoctl(*socket, SIO_UDP_CONNRESET, &bNewBehavior, sizeof(bNewBehavior), 
                    NULL, 0, &dwBytesReturned, NULL, NULL);
                ec = check_int_error(ret);
            }

            return ec;
        }
#else
        inline errorcode_t turn_off_conn_reset_notifications_on_recv(const socket_t& socket)
        {
            return check_socket_valid(socket);
        }
#endif

        template<class T>
        class server_real_impl : public simple_server_itf
        {
        public:
            server_real_impl(std::unique_ptr<T>&& srv_impl, 
                socket_t server_socket,
                sockaddr_wrap server_addr) : 
                m_server_socket(server_socket),
                m_server_addr(server_addr),
                m_srv_impl(std::move(srv_impl)) 
            { 
            }

            ~server_real_impl() {
                shutdown();
            }

            void shutdown() {
                m_server_socket.reset();
                m_srv_impl.reset();
            }

            socket_t get_server_socket() {
                return m_server_socket;
            }

            const sockaddr_wrap& get_server_addr() {
                return m_server_addr;
            }

        private:
            socket_t m_server_socket;
            sockaddr_wrap m_server_addr;
            std::unique_ptr<T> m_srv_impl;
        };

        inline void convert_any_addr_to_local(sockaddr_wrap& addr)
        {
            if (addr.is_any_addr())
            {
                switch (addr.get_family())
                {
                case AF_INET:
                    addr.set_ipv4_addr(INADDR_LOOPBACK);
                    break;
                case AF_INET6:
                    addr.set_ipv6_addr(in6_addr(IN6ADDR_LOOPBACK_INIT));
                    break;
                }
            }
        }
    }

    CPP_LITE_SOCKETS_FN std::pair<server_t, errorcode_t> tcpserver_create(
        const sockaddr_wrap& server_addr,
        std::function<void(socket_t client_socket, const sockaddr_wrap& client_addr)> fn_on_new_client,
        std::function<errorcode_t(socket_t server_socket)> fn_on_prepare_server_socket)
    {
        typedef std::function<void(socket_t client_socket, const sockaddr_wrap& client_addr)> fn_on_new_client_t;
        class tcp_server_impl
        {
        public:
            tcp_server_impl(socket_t server_socket, sockaddr_wrap server_addr, fn_on_new_client_t fn_on_new_client_) :
                m_server_socket(server_socket),
                m_server_addr(server_addr),
                m_fn_on_new_client(fn_on_new_client_),
                m_shutdown(false)
            {
            }

            errorcode_t start()
            {
                m_server_thread = std::thread([this]() { server_thread(); });
                return 0;
            }

            ~tcp_server_impl()
            {
                shutdown_thread();
            }

        private:
            void server_thread()
            {
                errorcode_t ec;
                CPP_LITE_SOCKETS__LOGGER("Started TCP server thread for the address: %s", m_server_addr.to_string().c_str());
                while (!m_shutdown.load())
                {
                    socket_t client_socket;
                    sockaddr_wrap sa;
                    std::tie(client_socket, sa, ec) = socket_accept(m_server_socket);
                    if (m_shutdown.load()) {
                        break;
                    }
                    if (ec != 0) {
                        CPP_LITE_SOCKETS__LOGGER("Error accepting new connection: %d", ec);
                        continue;
                    }
                    m_fn_on_new_client(client_socket, sa);
                }
                CPP_LITE_SOCKETS__LOGGER("Stopped TCP server thread for the address: %s", m_server_addr.to_string().c_str());
            }

            void shutdown_thread()
            {
                m_shutdown.store(true);
                if (0 == impl::check_socket_valid(m_server_socket) && m_server_thread.joinable())
                {
                    errorcode_t ec = socket_shutdown(m_server_socket, SHUT_RDWR);
                    if (ec != 0)
                    {
                        // ::shutdown don't work on windows for the server sockets, so we need:
                        // - to establish a fake connection to unblock the server thread or
                        // - to close server's socket
                        // Closing the server socket is dirty way and can cause synchronization problems, so we choose the first way.
                        socket_t socket;
                        std::tie(socket, ec) = socket_create_tcp(m_server_addr.get_family());
                        if (ec == 0)
                        {
                            sockaddr_wrap connect_addr = m_server_addr;
                            impl::convert_any_addr_to_local(connect_addr);
                            ec = socket_connect(socket, connect_addr);

                        }
                    }
                    // Using the second way if the first way was unsuccessful
                    if (ec != 0) {
                        m_server_socket.reset();
                    }
                }
                if (m_server_thread.joinable()) {
                    m_server_thread.join();
                }
                m_server_socket.reset();
            }

        private:
            socket_t m_server_socket;
            sockaddr_wrap m_server_addr;
            fn_on_new_client_t m_fn_on_new_client;
            std::thread m_server_thread;
            std::atomic<bool> m_shutdown;
        };

        std::pair<server_t, errorcode_t> res;
        auto& ec = res.second;
        socket_t server_socket;
        std::tie(server_socket, ec) = socket_create_tcp(server_addr.get_family());

        if (ec == 0) {
            if (fn_on_prepare_server_socket) {
                ec = fn_on_prepare_server_socket(server_socket);
            }
        }

        if (ec == 0) {
            ec = socket_bind(server_socket, server_addr);
        }

        sockaddr_wrap server_addr_effective;
        if (ec == 0) {
            std::tie(server_addr_effective, ec) = socket_getsockname(server_socket);
        }

        if (ec == 0) {
            ec = socket_listen(server_socket);
        }

        if (ec == 0) 
        {
            auto spSrv = STD_MAKE_UNIQUE(tcp_server_impl, server_socket, server_addr_effective, fn_on_new_client);
            ec = spSrv->start();

            if (ec == 0)
            {
                auto spResSrv = server_t(new impl::server_real_impl<tcp_server_impl>(
                    std::move(spSrv), server_socket, server_addr_effective));
                res.first = std::move(spResSrv);
            }
        }

        return res;
    }

    CPP_LITE_SOCKETS_FN std::pair<server_t, errorcode_t> udpserver_create(const sockaddr_wrap& server_addr,
        std::function<void(socket_t server_socket, const buff_t& datagram, const sockaddr_wrap& client_addr)> fn_on_data,
        std::function<errorcode_t(socket_t server_socket)> fn_on_prepare_server_socket/* = std::function<errorcode_t(socket_t server_socket)>()*/)
    {
        typedef std::function<void(socket_t server_socket, const buff_t& buff, const sockaddr_wrap& client_addr)> fn_on_data_t;
        class udp_server_impl
        {
        public:
            udp_server_impl(socket_t server_socket, sockaddr_wrap server_addr, fn_on_data_t fn_on_data_) :
                m_server_socket(server_socket),
                m_server_addr(server_addr),
                m_fn_on_data(fn_on_data_),
                m_shutdown(false)
            {
            }

            errorcode_t start()
            {
                m_server_thread = std::thread([this]() { server_thread(); });
                return 0;
            }

            ~udp_server_impl()
            {
                shutdown_thread();
            }

        private:
            void server_thread()
            {
                errorcode_t ec;
                sockaddr_wrap from_addr;
                std::vector<std::uint8_t> buff_data;
                buff_t buff;
                buff_data.resize(65536);

                CPP_LITE_SOCKETS__LOGGER("Started UDP server thread for the address: %s", m_server_addr.to_string().c_str());
                while (!m_shutdown.load())
                {
                    std::tie(buff, from_addr, ec) = socket_recv_from(m_server_socket, buff_t(buff_data));
                    if (m_shutdown.load()) {
                        break;
                    }
                    if (ec != 0) {
                        CPP_LITE_SOCKETS__LOGGER("Error receiving datagram: %d", ec);
                        continue;
                    }
                    m_fn_on_data(m_server_socket, buff, from_addr);
                }
                CPP_LITE_SOCKETS__LOGGER("Stopped UDP server thread for the address: %s", m_server_addr.to_string().c_str());
            }

            void shutdown_thread()
            {
                m_shutdown.store(true);
                if (0 == impl::check_socket_valid(m_server_socket) && m_server_thread.joinable())
                {
                    // ::shutdown don't work on datagram sockets, so we need:
                    // - to send a fake datagram to unblock the server thread or
                    // - to close server's socket
                    // Closing the server socket is dirty way and can cause synchronization problems, so we choose the first way.
                    errorcode_t ec;
                    socket_t socket;
                    std::tie(socket, ec) = socket_create_udp(m_server_addr.get_family());
                    if (ec == 0)
                    {
                        sockaddr_wrap target_addr = m_server_addr;
                        impl::convert_any_addr_to_local(target_addr);
                        size_t n_sent;
                        std::tie(n_sent, ec) = socket_send_to(socket, buff_t("", 1), target_addr);
                    }

                    // Using the second way if the first way was unsuccessful
                    if (ec != 0) {
                        m_server_socket.reset();
                    }
                }
                if (m_server_thread.joinable()) {
                    m_server_thread.join();
                }
                m_server_socket.reset();
            }

        private:
            socket_t m_server_socket;
            sockaddr_wrap m_server_addr;
            fn_on_data_t m_fn_on_data;
            std::thread m_server_thread;
            std::atomic<bool> m_shutdown;
        };

        std::pair<server_t, errorcode_t> res;
        auto& ec = res.second;
        socket_t server_socket;

        do 
        {
            std::tie(server_socket, ec) = socket_create_udp(server_addr.get_family());
            if (ec != 0) {
                break;
            }

            if (fn_on_prepare_server_socket) {
                ec = fn_on_prepare_server_socket(server_socket);
                if (ec != 0) {
                    break;
                }
            }

            ec = socket_bind(server_socket, server_addr);
            if (ec != 0) {
                break;
            }

            impl::turn_off_conn_reset_notifications_on_recv(server_socket);

            sockaddr_wrap server_addr_effective;
            std::tie(server_addr_effective, ec) = socket_getsockname(server_socket);
            if (ec != 0) {
                break;
            }

            auto spSrv = STD_MAKE_UNIQUE(udp_server_impl, server_socket, server_addr_effective, fn_on_data);
            ec = spSrv->start();
            if (ec != 0) {
                break;
            }

            auto spResSrv = server_t(new impl::server_real_impl<udp_server_impl>(
                std::move(spSrv), server_socket, server_addr_effective));
            res.first = std::move(spResSrv);
        } while (false);

        return res;
    }

    CPP_LITE_SOCKETS_FN std::uint16_t sockaddr_wrap::get_port() const
    {
        switch (sa.sa.sa_family)
        {
        case AF_INET:
            return ntohs(sa.sa_in4.sin_port);
        case AF_INET6:
            return ntohs(sa.sa_in6.sin6_port);
        }
        return 0;
    }

    CPP_LITE_SOCKETS_FN bool sockaddr_wrap::is_any_addr() const
    {
        typedef decltype(sa.sa_in4.sin_addr) TAddr4;
        static TAddr4 s_any_addr4 = TAddr4();
        typedef decltype(sa.sa_in6.sin6_addr) TAddr6;
        static TAddr6 s_any_addr6 = TAddr6(IN6ADDR_ANY_INIT);
        switch (sa.sa.sa_family)
        {
        case AF_INET:
        {
            return std::memcmp(&sa.sa_in4.sin_addr, &s_any_addr4, sizeof(s_any_addr4)) == 0;
        }
        case AF_INET6:
        {
            return std::memcmp(&sa.sa_in6.sin6_addr, &s_any_addr6, sizeof(s_any_addr6)) == 0;
        }
        }
        return false;
    }

    CPP_LITE_SOCKETS_FN bool sockaddr_wrap::is_local_addr() const
    {
        typedef decltype(sa.sa_in6.sin6_addr) TAddr6;
        static TAddr6 s_loopback_addr6 = TAddr6(IN6ADDR_LOOPBACK_INIT);
        switch (sa.sa.sa_family)
        {
        case AF_INET:
        {
            return (ntohl(sa.sa_in4.sin_addr.s_addr) & 0xFF000000u) == 0x7F000000u; // 127.x.x.x
        }
        case AF_INET6:
        {
            return std::memcmp(&sa.sa_in6.sin6_addr, &s_loopback_addr6, sizeof(s_loopback_addr6)) == 0;
        }
        }
        return false;
    }

    CPP_LITE_SOCKETS_FN std::string sockaddr_wrap::to_string(bool with_port/* = true*/, bool with_scope_id /*= true*/) const
    {
        const char* res = NULL;
        std::string res_str;
        errorcode_t ec = 0;
        char buff[INET6_ADDRSTRLEN + 1 /*\0*/];
        switch (sa.sa.sa_family)
        {
        case AF_UNSPEC:
            res = "unspecified";
            with_port = false;
            break;
        case AF_INET:
            res = ::inet_ntop(AF_INET, const_cast<void*>(static_cast<const void*>(&sa.sa_in4.sin_addr)), buff, sizeof(buff));
            if (!res) {
                ec = impl::get_last_error();
            }
            break;
        case AF_INET6:
            res = ::inet_ntop(AF_INET6, const_cast<void*>(static_cast<const void*>(&sa.sa_in6.sin6_addr)), buff, sizeof(buff));
            if (!res) {
                ec = impl::get_last_error();
            }
            break;
        default:
            res = "unsupported";
            with_port = false;
            break;
        }

        if (!res || ec != 0) {
            res = "error";
            with_port = false;
        }

        res_str = res;
        if (with_scope_id && sa.sa.sa_family == AF_INET6) {
            auto scope_id = get_ipv6_scope();
            if(scope_id) {
                res_str.append("%");
                res_str.append(std::to_string(scope_id));
            }
        }
        if (with_port) {
            auto port = get_port();
            if (port) {
                res_str.append(":");
                res_str.append(std::to_string(get_port()));
            }
        }
        return res_str;
    }

    CPP_LITE_SOCKETS_FN errorcode_t socket_getopt(const socket_t& socket, int level, int optname, void* optval, size_t optlen)
    {
        errorcode_t ec = impl::check_socket_valid(socket);
        if (ec == 0) {
            const socklen_t optlen_original = static_cast<socklen_t>(optlen);
            socklen_t optlen_value = optlen_original;
            ec = impl::check_int_error(::getsockopt(*socket, level, optname, static_cast<char*>(optval), &optlen_value));
            if (ec == 0 && optlen_value < optlen_original) {
                std::memset(static_cast<char*>(optval) + optlen_value, 0, optlen - optlen_value);
            }
        }
        return ec;
    }

    template<class T>
    CPP_LITE_SOCKETS_FN errorcode_t socket_getopt(const socket_t& socket, int level, int optname, T& optval)
    {
        return socket_getopt(socket, level, optname, &optval, sizeof(optval));
    }

    CPP_LITE_SOCKETS_FN errorcode_t socket_setopt(const socket_t& socket, int level, int optname, const void* optval, int optlen)
    {
        errorcode_t ec = impl::check_socket_valid(socket);
        if (ec == 0) {
            ec = impl::check_int_error(::setsockopt(*socket, level, optname, static_cast<const char*>(optval), optlen));
        }
        return ec;
    }

    template<class T>
    CPP_LITE_SOCKETS_FN errorcode_t socket_setopt(const socket_t& socket, int level, int optname, const T& optval)
    {
        return socket_setopt(socket, level, optname, &optval, sizeof(optval));
    }

    CPP_LITE_SOCKETS_FN errorcode_t socket_setopt_dualstack(const socket_t& socket, bool dualstack /*= true*/)
    {
        return socket_setopt<int>(socket, IPPROTO_IPV6, IPV6_V6ONLY, dualstack ? 0 : 1);
    }

    namespace impl
    {
        template<class T>
        inline std::pair<sockaddr_wrap, errorcode_t> socket_getxname(const socket_t& socket, T fn_getname)
        {
            std::pair<sockaddr_wrap, errorcode_t> res;
            errorcode_t& ec = res.second;
            sockaddr_wrap& sa = res.first;
            ec = impl::check_socket_valid(socket);
            if (ec == 0) {
                socklen_t len = sizeof(sa.sa);
                ec = impl::check_int_error(fn_getname(*socket, &sa.sa.sa, &len));
                if (ec == 0) {
                    sa.len = len;
                }
            }
            return res;
        }
    }

    CPP_LITE_SOCKETS_FN std::pair<sockaddr_wrap, errorcode_t> socket_getsockname(const socket_t& socket)
    {
        return impl::socket_getxname(socket, ::getsockname);
    }

    CPP_LITE_SOCKETS_FN std::pair<sockaddr_wrap, errorcode_t> socket_getpeername(const socket_t& socket)
    {
        return impl::socket_getxname(socket, ::getpeername);
    }

    CPP_LITE_SOCKETS_FN std::pair<size_t, errorcode_t> socket_send(const socket_t& socket, const buff_t& buff, int flags /*= 0*/)
    {
        std::pair<size_t, errorcode_t> res;
        errorcode_t& ec = res.second;
        size_t& n_sent = res.first;
        ec = impl::check_socket_valid(socket);
        if (ec == 0) 
        {
            int len = (buff.len > static_cast<size_t>(std::numeric_limits<int>::max())) ? 
                std::numeric_limits<int>::max() : static_cast<int>(buff.len);
            int send_res = ::send(*socket, static_cast<const char*>(buff.data), len, flags);
            ec = impl::check_int_error(send_res);
            if (ec == 0) {
                n_sent = send_res;
            }
        }
        return res;
    }

    CPP_LITE_SOCKETS_FN errorcode_t socket_send_all(const socket_t& socket, const buff_t& buff, int flags /*= 0*/)
    {
        auto data = static_cast<const std::uint8_t*>(buff.data);
        size_t len = buff.len;
        errorcode_t ec = 0;
        size_t n_sent;

        while (len > 0 && ec == 0)
        {
            buff_t cur_buff(data, len);
            std::tie(n_sent, ec) = socket_send(socket, cur_buff, flags);
            if (ec != 0) {
                break;
            }
            len -= n_sent;
            data += n_sent;
        }
        return ec;
    }

    CPP_LITE_SOCKETS_FN std::pair<buff_t, errorcode_t> socket_recv(const socket_t& socket, const buff_t& buff, int flags /*= 0*/)
    {
        std::pair<buff_t, errorcode_t> res;
        errorcode_t& ec = res.second;
        ec = impl::check_socket_valid(socket);
        auto& res_buff = res.first;
        int len = (buff.len > static_cast<size_t>(std::numeric_limits<int>::max())) ?
            std::numeric_limits<int>::max() : static_cast<int>(buff.len);
        res_buff.data = buff.data;
        res_buff.len = 0;
        if (ec == 0)
        {
            int recv_res = ::recv(*socket, static_cast<char*>(buff.data), len, flags);
            ec = impl::check_int_error(recv_res);
            if (ec == 0) {
                if (recv_res > 0) {
                    res_buff.len = static_cast<size_t>(recv_res);
                }
                else {
                    ec = ECLS_CONNGRACEFULLYCLOSED; // The connection has been gracefully closed
                }
            }
        }
        return res;
    }

    CPP_LITE_SOCKETS_FN std::pair<buff_t, errorcode_t> socket_recv_all(const socket_t& socket, const buff_t& buff, int flags /*= 0*/)
    {
        std::pair<buff_t, errorcode_t> res;
        auto data = static_cast<const std::uint8_t*>(buff.data);
        size_t len = buff.len;
        auto& res_buff = res.first;
        errorcode_t& ec = res.second;
        ec = 0;

        res_buff.data = buff.data;
        res_buff.len = 0;

        while (len > 0 && ec == 0)
        {
            buff_t cur_buff(data, len);
            std::tie(cur_buff, ec) = socket_recv(socket, cur_buff, flags);
            if (ec != 0 || cur_buff.len == 0) {
                break;
            }
            len -= cur_buff.len;
            data += cur_buff.len;
            res_buff.len += cur_buff.len;
        }
        return res;
    }

    CPP_LITE_SOCKETS_FN std::tuple<buff_t, sockaddr_wrap, errorcode_t> socket_recv_from(const socket_t& socket, const buff_t& buff, int flags /*= 0*/)
    {
        std::tuple<buff_t, sockaddr_wrap, errorcode_t> res;
        auto& res_buff = std::get<0>(res);
        auto& from_addr = std::get<1>(res);
        errorcode_t& ec = std::get<2>(res);
        ec = impl::check_socket_valid(socket);
        int len = (buff.len > static_cast<size_t>(std::numeric_limits<int>::max())) ?
            std::numeric_limits<int>::max() : static_cast<int>(buff.len);
        res_buff.data = buff.data;
        res_buff.len = 0;
        from_addr.len = 0;
        if (ec == 0)
        {
            socklen_t from_len = sizeof(from_addr.sa);
            
            int recv_res = ::recvfrom(*socket, static_cast<char*>(buff.data), len, flags, &from_addr.sa.sa, &from_len);
            ec = impl::check_int_error(recv_res);
            if (ec == 0) {
                res_buff.len = static_cast<size_t>(recv_res);
                from_addr.len = from_len;
            }
        }
        return res;
    }

    // Send datagram (sendto wrapper)
    CPP_LITE_SOCKETS_FN std::pair<size_t, errorcode_t> socket_send_to(const socket_t& socket, const buff_t& buff, const sockaddr_wrap& to_addr, int flags /*= 0*/)
    {
        std::pair<size_t, errorcode_t> res;
        errorcode_t& ec = res.second;
        size_t& n_sent = res.first;
        ec = impl::check_socket_valid(socket);
        if (ec == 0)
        {
            int len = (buff.len > static_cast<size_t>(std::numeric_limits<int>::max())) ?
                std::numeric_limits<int>::max() : static_cast<int>(buff.len);
            int send_res = ::sendto(*socket, static_cast<const char*>(buff.data), len, flags, to_addr, to_addr.get_len());
            ec = impl::check_int_error(send_res);
            if (ec == 0) {
                n_sent = send_res;
            }
        }
        return res;
    }
} // namespace cpp_lite_sockets

#endif // __CPP_LITE_SOCKETS__INCLUDED__