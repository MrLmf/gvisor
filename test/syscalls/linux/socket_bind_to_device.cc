// Copyright 2019 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "test/syscalls/linux/socket_bind_to_device.h"

#include <arpa/inet.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#include <cstdio>
#include <cstring>
#include <map>
#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "gtest/gtest.h"
#include "test/syscalls/linux/ip_socket_test_util.h"
#include "test/syscalls/linux/socket_test_util.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"
#include "test/util/uid_util.h"

namespace gvisor {
namespace testing {

using std::string;
using std::vector;

std::unordered_set<string> get_interface_names() {
  struct if_nameindex* interfaces = if_nameindex();
  if (interfaces == nullptr) {
    return {};
  }
  std::unordered_set<string> names;
  for (auto interface = interfaces;
       interface->if_index != 0 || interface->if_name != nullptr; interface++) {
    names.insert(interface->if_name);
  }
  if_freenameindex(interfaces);
  return names;
}

Tunnel::Tunnel(std::string tunnel_name) {
  fd_ = open("/dev/net/tun", O_RDWR);
  if (fd_ < 0) {
    return;
  }

  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_flags = IFF_TUN;
  strncpy(ifr.ifr_name, tunnel_name.c_str(), sizeof(ifr.ifr_name));

  int err = ioctl(fd_, (TUNSETIFF), (void*)&ifr);
  if (err < 0) {
    close(fd_);
    fd_ = -1;
  }
  name_ = ifr.ifr_name;
}

// Tests the creation of a seires of sockets with varying SO_BINDTODEVICE and
// SO_REUSEPORT options.  Uses consecutive ethernet devices named "eth1",
// "eth2", etc until they run out and then creates tunnel devices as needed.
TEST_P(BindToDeviceSequenceTest, BindToDevice) {
  auto test_case = ::testing::get<1>(GetParam());
  auto test_name = test_case.name;
  auto test_actions = test_case.actions;

  auto interface_names = get_interface_names();
  // devices maps from the device id in the test case to the name of the device.
  std::unordered_map<int, string> devices;
  int next_unused_eth = 1;
  std::vector<std::unique_ptr<Tunnel>> tunnels;
  for (const auto& action : test_actions) {
    if (action.device != 0 && devices.find(action.device) == devices.end()) {
      // Need to pick a new device.
      devices[action.device] = absl::StrCat("eth", next_unused_eth);
      next_unused_eth++;

      if (interface_names.find(devices[action.device]) ==
          interface_names.end()) {
        // gVisor tests should have enough ethernet devices to never reach here.
        ASSERT_FALSE(IsRunningOnGvisor());
        // Need a tunnel.
        tunnels.push_back(NewTunnel());
        devices[action.device] = tunnels.back()->GetName();
      }
    }
  }

  SCOPED_TRACE(
      absl::StrCat(::testing::get<0>(GetParam()).description, ", ", test_name));

  int action_index = 0;
  // sockets_to_close is a map from action index to the socket that was created.
  std::unordered_map<int,
                     std::unique_ptr<gvisor::testing::FileDescriptor>>
      sockets_to_close;
  // All the actions will use the same port, whichever we are assigned.
  in_port_t port = htons(0);
  for (const auto& action : test_actions) {
    SCOPED_TRACE(absl::StrCat("Action index: ", action_index));
    if (action.release) {
      // Close the socket that was made in a previous action.  The release_row
      // indicates which socket to close based on index into the list of
      // actions.
      sockets_to_close.erase(action.release_row);
      continue;
    }

    // Make the socket.
    sockets_to_close[action_index] = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());
    auto socket_fd = sockets_to_close[action_index]->get();
    action_index++;

    // If reuse is indicated, do that.
    if (action.reuse) {
      EXPECT_THAT(setsockopt(socket_fd, SOL_SOCKET, SO_REUSEPORT, &kSockOptOn,
                             sizeof(kSockOptOn)),
                  SyscallSucceedsWithValue(0));
    }

    // If the device is non-zero, bind to that device.
    if (action.device != 0) {
      string device_name = devices[action.device];
      EXPECT_THAT(setsockopt(socket_fd, SOL_SOCKET, SO_BINDTODEVICE,
                             device_name.c_str(), device_name.size() + 1),
                  SyscallSucceedsWithValue(0));
      char getDevice[100];
      socklen_t get_device_size = 100;
      EXPECT_THAT(getsockopt(socket_fd, SOL_SOCKET, SO_BINDTODEVICE, getDevice,
                             &get_device_size),
                  SyscallSucceedsWithValue(0));
    }

    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = port;
    if (action.want == 0) {
      ASSERT_THAT(
          bind(socket_fd, reinterpret_cast<const struct sockaddr*>(&addr),
               sizeof(addr)),
          SyscallSucceeds());
    } else {
      ASSERT_THAT(
          bind(socket_fd, reinterpret_cast<const struct sockaddr*>(&addr),
               sizeof(addr)),
          SyscallFailsWithErrno(action.want));
    }

    if (port == 0) {
      // We don't yet know what port we'll be using so we need to fetch it and
      // remember it for future commands.
      socklen_t addr_size = sizeof(addr);
      ASSERT_THAT(
          getsockname(socket_fd, reinterpret_cast<struct sockaddr*>(&addr),
                      &addr_size),
          SyscallSucceeds());
      port = addr.sin_port;
    }
  }
}

// Tests getsockopt of the default value.
TEST_P(BindToDeviceTest, GetsockoptDefault) {
  char name_buffer[IFNAMSIZ * 2];
  socklen_t name_buffer_size;

  // Read the default SO_BINDTODEVICE.
  for (int i = 0; i <= sizeof(name_buffer); i++) {
    memset(name_buffer, 'a', sizeof(name_buffer));
    name_buffer_size = i;
    EXPECT_THAT(getsockopt(GetSocketFd(), SOL_SOCKET, SO_BINDTODEVICE,
                           name_buffer, &name_buffer_size),
                SyscallSucceedsWithValue(0));
    EXPECT_EQ(name_buffer_size, 0);
  }
}

// Tests setsockopt of invalid device name.
TEST_P(BindToDeviceTest, SetsockoptInvalidDeviceName) {
  char name_buffer[IFNAMSIZ * 2];
  socklen_t name_buffer_size;

  // Set an invalid device name.
  memset(name_buffer, 'a', 5);
  name_buffer_size = 5;
  EXPECT_THAT(setsockopt(GetSocketFd(), SOL_SOCKET, SO_BINDTODEVICE,
                         name_buffer, name_buffer_size),
              SyscallFailsWithErrno(ENODEV));
}

// Tests setsockopt of a buffer with a valid device name but not
// null-terminated, with different sizes of buffer.
TEST_P(BindToDeviceTest, SetsockoptValidDeviceNameWithoutNullTermination) {
  char name_buffer[IFNAMSIZ * 2];
  socklen_t name_buffer_size;

  safestrncpy(name_buffer, GetInterfaceName().c_str(),
              GetInterfaceName().size() + 1);
  // Intentionally overwrite the null at the end.
  memset(name_buffer + GetInterfaceName().size(), 'a',
         sizeof(name_buffer) - GetInterfaceName().size());
  for (int i = 1; i <= sizeof(name_buffer); i++) {
    name_buffer_size = i;
    SCOPED_TRACE(absl::StrCat("Buffer size: ", i));
    // It should only work if the size provided is exactly right.
    if (name_buffer_size == GetInterfaceName().size()) {
      EXPECT_THAT(setsockopt(GetSocketFd(), SOL_SOCKET, SO_BINDTODEVICE,
                             name_buffer, name_buffer_size),
                  SyscallSucceeds());
    } else {
      EXPECT_THAT(setsockopt(GetSocketFd(), SOL_SOCKET, SO_BINDTODEVICE,
                             name_buffer, name_buffer_size),
                  SyscallFailsWithErrno(ENODEV));
    }
  }
}

// Tests setsockopt of a buffer with a valid device name and null-terminated,
// with different sizes of buffer.
TEST_P(BindToDeviceTest, SetsockoptValidDeviceNameWithNullTermination) {
  char name_buffer[IFNAMSIZ * 2];
  socklen_t name_buffer_size;

  safestrncpy(name_buffer, GetInterfaceName().c_str(),
              GetInterfaceName().size() + 1);
  // Don't overwrite the null at the end.
  memset(name_buffer + GetInterfaceName().size() + 1, 'a',
         sizeof(name_buffer) - GetInterfaceName().size() - 1);
  for (int i = 1; i <= sizeof(name_buffer); i++) {
    name_buffer_size = i;
    SCOPED_TRACE(absl::StrCat("Buffer size: ", i));
    // It should only work if the size provided is at least the right size.
    if (name_buffer_size >= GetInterfaceName().size()) {
      EXPECT_THAT(setsockopt(GetSocketFd(), SOL_SOCKET, SO_BINDTODEVICE,
                             name_buffer, name_buffer_size),
                  SyscallSucceeds());
    } else {
      EXPECT_THAT(setsockopt(GetSocketFd(), SOL_SOCKET, SO_BINDTODEVICE,
                             name_buffer, name_buffer_size),
                  SyscallFailsWithErrno(ENODEV));
    }
  }
}

// Tests that setsockopt of an invalid device name doesn't unset the previous
// valid setsockopt.
TEST_P(BindToDeviceTest, SetsockoptValidThenInvalid) {
  char name_buffer[IFNAMSIZ * 2];
  socklen_t name_buffer_size;

  // Write successfully.
  strcpy(name_buffer, GetInterfaceName().c_str());
  EXPECT_THAT(setsockopt(GetSocketFd(), SOL_SOCKET, SO_BINDTODEVICE,
                         name_buffer, sizeof(name_buffer)),
              SyscallSucceeds());

  // Read it back successfully.
  memset(name_buffer, 'a', sizeof(name_buffer));
  name_buffer_size = sizeof(name_buffer);
  strcpy(name_buffer, GetInterfaceName().c_str());
  EXPECT_THAT(getsockopt(GetSocketFd(), SOL_SOCKET, SO_BINDTODEVICE,
                         name_buffer, &name_buffer_size),
              SyscallSucceeds());
  EXPECT_EQ(name_buffer_size, GetInterfaceName().size() + 1);
  EXPECT_STREQ(name_buffer, GetInterfaceName().c_str());

  // Write unsuccessfully.
  memset(name_buffer, 'a', sizeof(name_buffer));
  name_buffer_size = 5;
  EXPECT_THAT(setsockopt(GetSocketFd(), SOL_SOCKET, SO_BINDTODEVICE,
                         name_buffer, sizeof(name_buffer)),
              SyscallFailsWithErrno(ENODEV));

  // Read it back successfully, it's unchanged.
  memset(name_buffer, 'a', sizeof(name_buffer));
  name_buffer_size = sizeof(name_buffer);
  strcpy(name_buffer, GetInterfaceName().c_str());
  EXPECT_THAT(getsockopt(GetSocketFd(), SOL_SOCKET, SO_BINDTODEVICE,
                         name_buffer, &name_buffer_size),
              SyscallSucceeds());
  EXPECT_EQ(name_buffer_size, GetInterfaceName().size() + 1);
  EXPECT_STREQ(name_buffer, GetInterfaceName().c_str());
}

// Tests that setsockopt of zero-length string correctly unsets the previous
// value.
TEST_P(BindToDeviceTest, SetsockoptValidThenClear) {
  char name_buffer[IFNAMSIZ * 2];
  socklen_t name_buffer_size;

  // Write successfully.
  strcpy(name_buffer, GetInterfaceName().c_str());
  EXPECT_THAT(setsockopt(GetSocketFd(), SOL_SOCKET, SO_BINDTODEVICE,
                         name_buffer, sizeof(name_buffer)),
              SyscallSucceeds());

  // Read it back successfully.
  memset(name_buffer, 'a', sizeof(name_buffer));
  name_buffer_size = sizeof(name_buffer);
  strcpy(name_buffer, GetInterfaceName().c_str());
  EXPECT_THAT(getsockopt(GetSocketFd(), SOL_SOCKET, SO_BINDTODEVICE,
                         name_buffer, &name_buffer_size),
              SyscallSucceeds());
  EXPECT_EQ(name_buffer_size, GetInterfaceName().size() + 1);
  EXPECT_STREQ(name_buffer, GetInterfaceName().c_str());

  // Clear it successfully.
  memset(name_buffer, 'a', sizeof(name_buffer));
  name_buffer_size = 0;
  EXPECT_THAT(setsockopt(GetSocketFd(), SOL_SOCKET, SO_BINDTODEVICE,
                         name_buffer, name_buffer_size),
              SyscallSucceeds());

  // Read it back successfully, it's cleared.
  memset(name_buffer, 'a', sizeof(name_buffer));
  name_buffer_size = sizeof(name_buffer);
  EXPECT_THAT(getsockopt(GetSocketFd(), SOL_SOCKET, SO_BINDTODEVICE,
                         name_buffer, &name_buffer_size),
              SyscallSucceeds());
  EXPECT_EQ(name_buffer_size, 0);
}

// Tests that setsockopt of empty string correctly unsets the previous
// value.
TEST_P(BindToDeviceTest, SetsockoptValidThenClearWithNull) {
  char name_buffer[IFNAMSIZ * 2];
  socklen_t name_buffer_size;

  // Write successfully.
  strcpy(name_buffer, GetInterfaceName().c_str());
  EXPECT_THAT(setsockopt(GetSocketFd(), SOL_SOCKET, SO_BINDTODEVICE,
                         name_buffer, sizeof(name_buffer)),
              SyscallSucceeds());

  // Read it back successfully.
  memset(name_buffer, 'a', sizeof(name_buffer));
  name_buffer_size = sizeof(name_buffer);
  strcpy(name_buffer, GetInterfaceName().c_str());
  EXPECT_THAT(getsockopt(GetSocketFd(), SOL_SOCKET, SO_BINDTODEVICE,
                         name_buffer, &name_buffer_size),
              SyscallSucceeds());
  EXPECT_EQ(name_buffer_size, GetInterfaceName().size() + 1);
  EXPECT_STREQ(name_buffer, GetInterfaceName().c_str());

  // Clear it successfully.
  memset(name_buffer, 'a', sizeof(name_buffer));
  name_buffer[0] = 0;
  name_buffer_size = sizeof(name_buffer);
  EXPECT_THAT(setsockopt(GetSocketFd(), SOL_SOCKET, SO_BINDTODEVICE,
                         name_buffer, name_buffer_size),
              SyscallSucceeds());

  // Read it back successfully, it's cleared.
  memset(name_buffer, 'a', sizeof(name_buffer));
  name_buffer_size = sizeof(name_buffer);
  EXPECT_THAT(getsockopt(GetSocketFd(), SOL_SOCKET, SO_BINDTODEVICE,
                         name_buffer, &name_buffer_size),
              SyscallSucceeds());
  EXPECT_EQ(name_buffer_size, 0);
}

// Tests getsockopt with different buffer sizes.
TEST_P(BindToDeviceTest, GetsockoptDevice) {
  char name_buffer[IFNAMSIZ * 2];
  socklen_t name_buffer_size;

  // Write successfully.
  strcpy(name_buffer, GetInterfaceName().c_str());
  ASSERT_THAT(setsockopt(GetSocketFd(), SOL_SOCKET, SO_BINDTODEVICE,
                         name_buffer, sizeof(name_buffer)),
              SyscallSucceeds());

  // Read it back at various buffer sizes.
  for (int i = 0; i <= sizeof(name_buffer); i++) {
    memset(name_buffer, 'a', sizeof(name_buffer));
    name_buffer_size = i;
    SCOPED_TRACE(absl::StrCat("Buffer size: ", i));
    // Linux only allows a buffer at least IFNAMSIZ, even if less would suffice
    // for this interface name.
    if (name_buffer_size >= IFNAMSIZ) {
      EXPECT_THAT(getsockopt(GetSocketFd(), SOL_SOCKET, SO_BINDTODEVICE,
                             name_buffer, &name_buffer_size),
                  SyscallSucceeds());
      EXPECT_EQ(name_buffer_size, GetInterfaceName().size() + 1);
      EXPECT_STREQ(name_buffer, GetInterfaceName().c_str());
    } else {
      EXPECT_THAT(getsockopt(GetSocketFd(), SOL_SOCKET, SO_BINDTODEVICE,
                             name_buffer, &name_buffer_size),
                  SyscallFailsWithErrno(EINVAL));
      EXPECT_EQ(name_buffer_size, i);
    }
  }
}

PosixErrorOr<uint16_t> AddrPort(int family, sockaddr_storage const& addr) {
  switch (family) {
    case AF_INET:
      return static_cast<uint16_t>(
          reinterpret_cast<sockaddr_in const*>(&addr)->sin_port);
    case AF_INET6:
      return static_cast<uint16_t>(
          reinterpret_cast<sockaddr_in6 const*>(&addr)->sin6_port);
    default:
      return PosixError(EINVAL,
                        absl::StrCat("unknown socket family: ", family));
  }
}

PosixError SetAddrPort(int family, sockaddr_storage* addr, uint16_t port) {
  switch (family) {
    case AF_INET:
      reinterpret_cast<sockaddr_in*>(addr)->sin_port = port;
      return NoError();
    case AF_INET6:
      reinterpret_cast<sockaddr_in6*>(addr)->sin6_port = port;
      return NoError();
    default:
      return PosixError(EINVAL,
                        absl::StrCat("unknown socket family: ", family));
  }
}

TEST_P(BindToDeviceDistributionTest, Tcp) {
  auto const& param = GetParam();
  auto const& listener_connector = ::testing::get<0>(param);
  auto const& endpoints = ::testing::get<1>(param).endpoints;

  TestAddress const& listener = listener_connector.listener;
  TestAddress const& connector = listener_connector.connector;
  sockaddr_storage listen_addr = listener.addr;
  sockaddr_storage conn_addr = connector.addr;

  auto interface_names = get_interface_names();

  // Create the listening sockets.
  std::vector<FileDescriptor> listener_fds;
  std::vector<std::unique_ptr<Tunnel>> all_tunnels;
  for (const auto& endpoint : endpoints) {
    if (interface_names.find(endpoint.bind_to_device) ==
        interface_names.end()) {
      all_tunnels.push_back(NewTunnel(endpoint.bind_to_device));
      interface_names.insert(endpoint.bind_to_device);
    }

    listener_fds.push_back(ASSERT_NO_ERRNO_AND_VALUE(
        Socket(listener.family(), SOCK_STREAM, IPPROTO_TCP)));
    int fd = listener_fds.back().get();

    ASSERT_THAT(setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &kSockOptOn,
                           sizeof(kSockOptOn)),
                SyscallSucceeds());
    ASSERT_THAT(setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
                           endpoint.bind_to_device.c_str(),
                           endpoint.bind_to_device.size() + 1),
                SyscallSucceeds());
    ASSERT_THAT(
        bind(fd, reinterpret_cast<sockaddr*>(&listen_addr), listener.addr_len),
        SyscallSucceeds());
    ASSERT_THAT(listen(fd, 40), SyscallSucceeds());

    // On the first bind we need to determine which port was bound.
    if (listener_fds.size() > 1) {
      continue;
    }

    // Get the port bound by the listening socket.
    socklen_t addrlen = listener.addr_len;
    ASSERT_THAT(
        getsockname(listener_fds[0].get(),
                    reinterpret_cast<sockaddr*>(&listen_addr), &addrlen),
        SyscallSucceeds());
    uint16_t const port =
        ASSERT_NO_ERRNO_AND_VALUE(AddrPort(listener.family(), listen_addr));
    ASSERT_NO_ERRNO(SetAddrPort(listener.family(), &listen_addr, port));
    ASSERT_NO_ERRNO(SetAddrPort(connector.family(), &conn_addr, port));
  }

  constexpr int kConnectAttempts = 10000;
  std::atomic<int> connects_received = ATOMIC_VAR_INIT(0);
  std::vector<std::unique_ptr<ScopedThread>> listen_threads;
  std::vector<std::shared_ptr<int>> accept_counts;
  // TODO(avagin): figure how to not disable S/R for the whole test.
  // We need to take into account that this test executes a lot of system
  // calls from many threads.
  DisableSave ds;

  for (const auto& listener_fd : listener_fds) {
    std::shared_ptr<int> accept_count = std::make_shared<int>(0);
    accept_counts.push_back(accept_count);
    listen_threads.push_back(absl::make_unique<ScopedThread>(
        [&listener_fd, &listener_fds, accept_count, &connects_received]() {
          do {
            auto fd = Accept(listener_fd.get(), nullptr, nullptr);
            if (!fd.ok()) {
              if (connects_received >= kConnectAttempts) {
                // Another thread have shutdown our read side causing the
                // accept to fail.
                return;
              }
              ASSERT_NO_ERRNO(fd);
              break;
            }
            // Receive some data from a socket to be sure that the connect()
            // system call has been completed on another side.
            int data;
            EXPECT_THAT(
                RetryEINTR(recv)(fd.ValueOrDie().get(), &data, sizeof(data), 0),
                SyscallSucceedsWithValue(sizeof(data)));
            (*accept_count)++;
          } while (++connects_received < kConnectAttempts);

          // Shutdown all sockets to wake up other threads.
          for (const auto& listener_fd : listener_fds) {
            shutdown(listener_fd.get(), SHUT_RDWR);
          }
        }));
  }

  for (int i = 0; i < kConnectAttempts; i++) {
    const FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(
        Socket(connector.family(), SOCK_STREAM, IPPROTO_TCP));
    ASSERT_THAT(
        RetryEINTR(connect)(fd.get(), reinterpret_cast<sockaddr*>(&conn_addr),
                            connector.addr_len),
        SyscallSucceeds());

    EXPECT_THAT(RetryEINTR(send)(fd.get(), &i, sizeof(i), 0),
                SyscallSucceedsWithValue(sizeof(i)));
  }

  // Join threads to be sure that all connections have been counted.
  for (const auto& listen_thread : listen_threads) {
    listen_thread->Join();
  }
  // Check that connections are distributed fairly between listening sockets
  for (int i = 0; i < accept_counts.size(); i++) {
    EXPECT_THAT(*accept_counts[i],
                EquivalentWithin(
                    int(kConnectAttempts * endpoints[i].expected_ratio), 0.10))
        << "endpoint " << i << " got the wrong number of packets";
  }
}

TEST_P(BindToDeviceDistributionTest, Udp) {
  auto const& param = GetParam();
  auto const& listener_connector = ::testing::get<0>(param);
  auto const& endpoints = ::testing::get<1>(param).endpoints;

  TestAddress const& listener = listener_connector.listener;
  TestAddress const& connector = listener_connector.connector;
  sockaddr_storage listen_addr = listener.addr;
  sockaddr_storage conn_addr = connector.addr;

  auto interface_names = get_interface_names();

  // Create the listening socket.
  std::vector<FileDescriptor> listener_fds;
  std::vector<std::unique_ptr<Tunnel>> all_tunnels;
  for (const auto& endpoint : endpoints) {
    if (interface_names.find(endpoint.bind_to_device) ==
        interface_names.end()) {
      all_tunnels.push_back(NewTunnel(endpoint.bind_to_device));
      interface_names.insert(endpoint.bind_to_device);
    }

    listener_fds.push_back(
        ASSERT_NO_ERRNO_AND_VALUE(Socket(listener.family(), SOCK_DGRAM, 0)));
    int fd = listener_fds.back().get();

    ASSERT_THAT(setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &kSockOptOn,
                           sizeof(kSockOptOn)),
                SyscallSucceeds());
    ASSERT_THAT(setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
                           endpoint.bind_to_device.c_str(),
                           endpoint.bind_to_device.size() + 1),
                SyscallSucceeds());
    ASSERT_THAT(
        bind(fd, reinterpret_cast<sockaddr*>(&listen_addr), listener.addr_len),
        SyscallSucceeds());

    // On the first bind we need to determine which port was bound.
    if (listener_fds.size() > 1) {
      continue;
    }

    // Get the port bound by the listening socket.
    socklen_t addrlen = listener.addr_len;
    ASSERT_THAT(
        getsockname(listener_fds[0].get(),
                    reinterpret_cast<sockaddr*>(&listen_addr), &addrlen),
        SyscallSucceeds());
    uint16_t const port =
        ASSERT_NO_ERRNO_AND_VALUE(AddrPort(listener.family(), listen_addr));
    ASSERT_NO_ERRNO(SetAddrPort(listener.family(), &listen_addr, port));
    ASSERT_NO_ERRNO(SetAddrPort(connector.family(), &conn_addr, port));
  }

  constexpr int kConnectAttempts = 10000;
  std::atomic<int> packets_received = ATOMIC_VAR_INIT(0);
  std::vector<std::unique_ptr<ScopedThread>> receiver_threads;
  std::vector<std::shared_ptr<int>> packets_per_socket;
  // TODO(avagin): figure how to not disable S/R for the whole test.
  DisableSave ds;  // Too expensive.

  for (const auto& listener_fd : listener_fds) {
    std::shared_ptr<int> packet_per_socket = std::make_shared<int>(0);
    packets_per_socket.push_back(packet_per_socket);
    receiver_threads.push_back(absl::make_unique<ScopedThread>(
        [&listener_fd, &listener_fds, packet_per_socket, &packets_received]() {
          do {
            struct sockaddr_storage addr = {};
            socklen_t addrlen = sizeof(addr);
            int data;

            auto ret = RetryEINTR(recvfrom)(
                listener_fd.get(), &data, sizeof(data), 0,
                reinterpret_cast<struct sockaddr*>(&addr), &addrlen);

            if (packets_received < kConnectAttempts) {
              ASSERT_THAT(ret, SyscallSucceedsWithValue(sizeof(data)));
            }

            if (ret != sizeof(data)) {
              // Another thread may have shutdown our read side causing the
              // recvfrom to fail.
              break;
            }

            packets_received++;
            (*packet_per_socket)++;

            // A response is required to synchronize with the main thread,
            // otherwise the main thread can send more than can fit into receive
            // queues.
            EXPECT_THAT(
                RetryEINTR(sendto)(listener_fd.get(), &data, sizeof(data), 0,
                                   reinterpret_cast<sockaddr*>(&addr), addrlen),
                SyscallSucceedsWithValue(sizeof(data)));
          } while (packets_received < kConnectAttempts);

          // Shutdown all sockets to wake up other threads.
          for (const auto& listener_fd : listener_fds) {
            shutdown(listener_fd.get(), SHUT_RDWR);
          }
        }));
  }

  for (int i = 0; i < kConnectAttempts; i++) {
    const FileDescriptor fd =
        ASSERT_NO_ERRNO_AND_VALUE(Socket(connector.family(), SOCK_DGRAM, 0));
    EXPECT_THAT(RetryEINTR(sendto)(fd.get(), &i, sizeof(i), 0,
                                   reinterpret_cast<sockaddr*>(&conn_addr),
                                   connector.addr_len),
                SyscallSucceedsWithValue(sizeof(i)));
    int data;
    EXPECT_THAT(RetryEINTR(recv)(fd.get(), &data, sizeof(data), 0),
                SyscallSucceedsWithValue(sizeof(data)));
  }

  // Join threads to be sure that all connections have been counted
  for (const auto& receiver_thread : receiver_threads) {
    receiver_thread->Join();
  }
  // Check that packets are distributed fairly between listening sockets.
  for (int i = 0; i < packets_per_socket.size(); i++) {
    EXPECT_THAT(*packets_per_socket[i],
                EquivalentWithin(
                    int(kConnectAttempts * endpoints[i].expected_ratio), 0.10));
  }
}

}  // namespace testing
}  // namespace gvisor
