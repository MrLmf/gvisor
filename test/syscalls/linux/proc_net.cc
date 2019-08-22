// Copyright 2018 The gVisor Authors.
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

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>

#include "gtest/gtest.h"
#include "gtest/gtest.h"
#include "test/syscalls/linux/socket_test_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {
namespace {

TEST(ProcNetIfInet6, Format) {
  auto ifinet6 = ASSERT_NO_ERRNO_AND_VALUE(GetContents("/proc/net/if_inet6"));
  EXPECT_THAT(ifinet6,
              ::testing::MatchesRegex(
                  // Ex: "00000000000000000000000000000001 01 80 10 80 lo\n"
                  "^([a-f\\d]{32}( [a-f\\d]{2}){4} +[a-z][a-z\\d]*\\n)+$"));
}

TEST(ProcSysNetIpv4Sack, Exists) {
  EXPECT_THAT(open("/proc/sys/net/ipv4/tcp_sack", O_RDONLY), SyscallSucceeds());
}

TEST(ProcSysNetIpv4Sack, CanReadAndWrite) {
  auto const fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/proc/sys/net/ipv4/tcp_sack", O_RDWR));

  char buf;
  EXPECT_THAT(PreadFd(fd.get(), &buf, sizeof(buf), 0),
              SyscallSucceedsWithValue(sizeof(buf)));

  EXPECT_TRUE(buf == '0' || buf == '1') << "unexpected tcp_sack: " << buf;

  char to_write = (buf == '1') ? '0' : '1';
  EXPECT_THAT(PwriteFd(fd.get(), &to_write, sizeof(to_write), 0),
              SyscallSucceedsWithValue(sizeof(to_write)));

  buf = 0;
  EXPECT_THAT(PreadFd(fd.get(), &buf, sizeof(buf), 0),
              SyscallSucceedsWithValue(sizeof(buf)));
  EXPECT_EQ(buf, to_write);
}

PosixErrorOr<uint64_t> get_metric(std::string snmp, const char *type,
                                  const char *item) {
  int idx = -1;

  for (auto const &line : absl::StrSplit(snmp, '\n')) {
    if (!absl::StartsWith(line, type)) continue;

    std::vector<std::string> fields =
        absl::StrSplit(line, ' ', absl::SkipWhitespace());
    EXPECT_TRUE(!fields.empty());

    if (idx == -1) {
      for (size_t i = 1; i < fields.size(); i++) {
        if (fields[i].compare(item) == 0) {
          idx = i;
          break;
        }
      }
      continue;
    }

    uint64_t val;
    if (!absl::SimpleAtoi(fields[idx], &val))
      return PosixError(EINVAL,
                        absl::StrCat("field is not a number: ", fields[idx]));

    return val;
  }

  return PosixError(
      EINVAL, absl::StrCat("failed to find ", type, "/", item, " in:", snmp));
}

TEST(ProcNetSnmp, TcpReset) {
  uint64_t oldAttemptFails;
  uint64_t oldActiveOpens;
  uint64_t oldOutRsts;
  auto snmp = ASSERT_NO_ERRNO_AND_VALUE(GetContents("/proc/net/snmp"));
  oldActiveOpens =
      ASSERT_NO_ERRNO_AND_VALUE(get_metric(snmp, "Tcp", "ActiveOpens"));
  oldOutRsts = ASSERT_NO_ERRNO_AND_VALUE(get_metric(snmp, "Tcp", "OutRsts"));
  oldAttemptFails =
      ASSERT_NO_ERRNO_AND_VALUE(get_metric(snmp, "Tcp", "AttemptFails"));

  FileDescriptor s = ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_STREAM, 0));

  struct sockaddr_in sin = {
      .sin_family = AF_INET,
      .sin_port = htons(1234),
  };
  sin.sin_addr.s_addr = inet_addr("127.0.0.1");
  ASSERT_THAT(connect(s.get(), (struct sockaddr *)&sin, sizeof(sin)),
              SyscallFailsWithErrno(ECONNREFUSED));

  uint64_t newAttemptFails;
  uint64_t newActiveOpens;
  uint64_t newOutRsts;
  snmp = ASSERT_NO_ERRNO_AND_VALUE(GetContents("/proc/net/snmp"));
  newActiveOpens =
      ASSERT_NO_ERRNO_AND_VALUE(get_metric(snmp, "Tcp", "ActiveOpens"));
  newOutRsts = ASSERT_NO_ERRNO_AND_VALUE(get_metric(snmp, "Tcp", "OutRsts"));
  newAttemptFails =
      ASSERT_NO_ERRNO_AND_VALUE(get_metric(snmp, "Tcp", "AttemptFails"));

  EXPECT_EQ(oldActiveOpens, newActiveOpens - 1);
  EXPECT_EQ(oldOutRsts, newOutRsts - 1);
  EXPECT_EQ(oldAttemptFails, newAttemptFails - 1);
}

TEST(ProcNetSnmp, TcpEstab) {
  uint64_t oldEstabResets;
  uint64_t oldActiveOpens;
  uint64_t oldPassiveOpens;
  uint64_t oldCurrEstab;
  auto snmp = ASSERT_NO_ERRNO_AND_VALUE(GetContents("/proc/net/snmp"));
  oldActiveOpens =
      ASSERT_NO_ERRNO_AND_VALUE(get_metric(snmp, "Tcp", "ActiveOpens"));
  oldPassiveOpens =
      ASSERT_NO_ERRNO_AND_VALUE(get_metric(snmp, "Tcp", "PassiveOpens"));
  oldCurrEstab =
      ASSERT_NO_ERRNO_AND_VALUE(get_metric(snmp, "Tcp", "CurrEstab"));
  oldEstabResets =
      ASSERT_NO_ERRNO_AND_VALUE(get_metric(snmp, "Tcp", "EstabResets"));

  FileDescriptor s_listen =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_STREAM, 0));

  struct sockaddr_in sin = {
      .sin_family = AF_INET,
      .sin_port = htons(1234),
  };
  sin.sin_addr.s_addr = inet_addr("127.0.0.1");
  ASSERT_THAT(bind(s_listen.get(), (struct sockaddr *)&sin, sizeof(sin)),
              SyscallSucceeds());
  ASSERT_THAT(listen(s_listen.get(), 1), SyscallSucceeds());

  FileDescriptor s_connect =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_STREAM, 0));
  ASSERT_THAT(connect(s_connect.get(), (struct sockaddr *)&sin, sizeof(sin)),
              SyscallSucceeds());

  auto s_accept =
      ASSERT_NO_ERRNO_AND_VALUE(Accept(s_listen.get(), nullptr, nullptr));

  uint64_t newEstabResets;
  uint64_t newActiveOpens;
  uint64_t newPassiveOpens;
  uint64_t newCurrEstab;
  snmp = ASSERT_NO_ERRNO_AND_VALUE(GetContents("/proc/net/snmp"));
  newActiveOpens =
      ASSERT_NO_ERRNO_AND_VALUE(get_metric(snmp, "Tcp", "ActiveOpens"));
  newPassiveOpens =
      ASSERT_NO_ERRNO_AND_VALUE(get_metric(snmp, "Tcp", "PassiveOpens"));
  newCurrEstab =
      ASSERT_NO_ERRNO_AND_VALUE(get_metric(snmp, "Tcp", "CurrEstab"));

  EXPECT_EQ(oldActiveOpens, newActiveOpens - 1);
  EXPECT_EQ(oldPassiveOpens, newPassiveOpens - 1);
  EXPECT_EQ(oldCurrEstab, newCurrEstab - 2);

  ASSERT_THAT(send(s_connect.get(), "a", 1, 0), SyscallSucceedsWithValue(1));

  s_accept.reset(-1);
  s_connect.reset(-1);

  snmp = ASSERT_NO_ERRNO_AND_VALUE(GetContents("/proc/net/snmp"));
  newCurrEstab =
      ASSERT_NO_ERRNO_AND_VALUE(get_metric(snmp, "Tcp", "CurrEstab"));
  newEstabResets =
      ASSERT_NO_ERRNO_AND_VALUE(get_metric(snmp, "Tcp", "EstabResets"));

  EXPECT_EQ(oldCurrEstab, newCurrEstab);
  EXPECT_EQ(oldEstabResets, newEstabResets - 2);
}

TEST(ProcNetSnmp, UdpNoPorts) {
  uint64_t oldOutDatagrams;
  uint64_t oldNoPorts;
  auto snmp = ASSERT_NO_ERRNO_AND_VALUE(GetContents("/proc/net/snmp"));
  oldOutDatagrams =
      ASSERT_NO_ERRNO_AND_VALUE(get_metric(snmp, "Udp", "OutDatagrams"));
  oldNoPorts = ASSERT_NO_ERRNO_AND_VALUE(get_metric(snmp, "Udp", "NoPorts"));

  FileDescriptor s = ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_DGRAM, 0));

  struct sockaddr_in sin = {
      .sin_family = AF_INET,
      .sin_port = htons(1234),
  };
  sin.sin_addr.s_addr = inet_addr("127.0.0.1");
  ASSERT_THAT(sendto(s.get(), "a", 1, 0, (struct sockaddr *)&sin, sizeof(sin)),
              SyscallSucceedsWithValue(1));

  uint64_t newOutDatagrams;
  uint64_t newNoPorts;
  snmp = ASSERT_NO_ERRNO_AND_VALUE(GetContents("/proc/net/snmp"));
  newOutDatagrams =
      ASSERT_NO_ERRNO_AND_VALUE(get_metric(snmp, "Udp", "OutDatagrams"));
  newNoPorts = ASSERT_NO_ERRNO_AND_VALUE(get_metric(snmp, "Udp", "NoPorts"));

  EXPECT_EQ(oldOutDatagrams, newOutDatagrams - 1);
  EXPECT_EQ(oldNoPorts, newNoPorts - 1);
}

TEST(ProcNetSnmp, UdpIn) {
  uint64_t oldOutDatagrams;
  uint64_t oldInDatagrams;
  auto snmp = ASSERT_NO_ERRNO_AND_VALUE(GetContents("/proc/net/snmp"));
  oldOutDatagrams =
      ASSERT_NO_ERRNO_AND_VALUE(get_metric(snmp, "Udp", "OutDatagrams"));
  oldInDatagrams =
      ASSERT_NO_ERRNO_AND_VALUE(get_metric(snmp, "Udp", "InDatagrams"));

  FileDescriptor server =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_DGRAM, 0));

  struct sockaddr_in sin = {
      .sin_family = AF_INET,
      .sin_port = htons(1234),
  };
  sin.sin_addr.s_addr = inet_addr("127.0.0.1");
  ASSERT_THAT(bind(server.get(), (struct sockaddr *)&sin, sizeof(sin)),
              SyscallSucceeds());

  FileDescriptor client =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_DGRAM, 0));
  ASSERT_THAT(
      sendto(client.get(), "a", 1, 0, (struct sockaddr *)&sin, sizeof(sin)),
      SyscallSucceedsWithValue(1));

  char buf[128];
  ASSERT_THAT(recvfrom(server.get(), buf, sizeof(buf), 0, NULL, NULL),
              SyscallSucceedsWithValue(1));

  uint64_t newOutDatagrams;
  uint64_t newInDatagrams;
  snmp = ASSERT_NO_ERRNO_AND_VALUE(GetContents("/proc/net/snmp"));
  newOutDatagrams =
      ASSERT_NO_ERRNO_AND_VALUE(get_metric(snmp, "Udp", "OutDatagrams"));
  newInDatagrams =
      ASSERT_NO_ERRNO_AND_VALUE(get_metric(snmp, "Udp", "InDatagrams"));

  EXPECT_EQ(oldOutDatagrams, newOutDatagrams - 1);
  EXPECT_EQ(oldInDatagrams, newInDatagrams - 1);
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
