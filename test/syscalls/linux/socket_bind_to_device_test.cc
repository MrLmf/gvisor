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

#include <vector>

#include "test/syscalls/linux/ip_socket_test_util.h"
#include "test/syscalls/linux/socket_test_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

SequenceTestAction NewSequenceTestAction(bool reuse, int device, bool release,
                                         int release_row, int want) {
  SequenceTestAction test_action;
  test_action.reuse = reuse;
  test_action.device = device;
  test_action.release = release;
  test_action.release_row = release_row;
  test_action.want = want;
  return test_action;
}

SequenceTestAction NewReleaseAction(int release_row) {
  return NewSequenceTestAction(false, 0, true, release_row, 0);
}

SequenceTestAction NewBindAction(bool reuse, int device, int want) {
  return NewSequenceTestAction(reuse, device, false, 0, want);
}

SequenceTestCase NewSequenceTestCase(string name,
                                     std::vector<SequenceTestAction> actions) {
  SequenceTestCase test_case;
  test_case.name = name;
  test_case.actions = actions;
  return test_case;
}

std::vector<SequenceTestCase> GetSequenceTestCases() {
  return std::vector<SequenceTestCase>{
      NewSequenceTestCase(
          "bind twice with device fails",
          {
              NewBindAction(/* reuse */ false, /* device */ 3, /* want */ 0),
              NewBindAction(/* reuse */ false, /* device */ 3,
                            /* want */ EADDRINUSE),
          }),
      NewSequenceTestCase(
          "bind to device",
          {
              NewBindAction(/* reuse */ false, /* device */ 1, /* want */ 0),
              NewBindAction(/* reuse */ false, /* device */ 2, /* want */ 0),
          }),
      NewSequenceTestCase(
          "bind to device and then without device",
          {
              NewBindAction(/* reuse */ false, /* device */ 123, /* want */ 0),
              NewBindAction(/* reuse */ false, /* device */ 0,
                            /* want */ EADDRINUSE),
          }),
      NewSequenceTestCase(
          "bind without device",
          {
              NewBindAction(/* reuse */ false, /* device */ 0, /* want */ 0),
              NewBindAction(/* reuse */ false, /* device */ 123,
                            /* want */ EADDRINUSE),
              NewBindAction(/* reuse */ true, /* device */ 123,
                            /* want */ EADDRINUSE),
              NewBindAction(/* reuse */ false, /* device */ 0,
                            /* want */ EADDRINUSE),
              NewBindAction(/* reuse */ true, /* device */ 0,
                            /* want */ EADDRINUSE),
          }),
      NewSequenceTestCase(
          "bind with device",
          {
              NewBindAction(/* reuse */ false, /* device */ 123, /* want */ 0),
              NewBindAction(/* reuse */ false, /* device */ 123,
                            /* want */ EADDRINUSE),
              NewBindAction(/* reuse */ true, /* device */ 123,
                            /* want */ EADDRINUSE),
              NewBindAction(/* reuse */ false, /* device */ 0,
                            /* want */ EADDRINUSE),
              NewBindAction(/* reuse */ true, /* device */ 0,
                            /* want */ EADDRINUSE),
              NewBindAction(/* reuse */ true, /* device */ 456, /* want */ 0),
              NewBindAction(/* reuse */ false, /* device */ 789, /* want */ 0),
              NewBindAction(/* reuse */ false, /* device */ 0,
                            /* want */ EADDRINUSE),
              NewBindAction(/* reuse */ true, /* device */ 0,
                            /* want */ EADDRINUSE),
          }),
      NewSequenceTestCase(
          "bind with reuse",
          {
              NewBindAction(/* reuse */ true, /* device */ 0, /* want */ 0),
              NewBindAction(/* reuse */ false, /* device */ 123,
                            /* want */ EADDRINUSE),
              NewBindAction(/* reuse */ true, /* device */ 123, /* want */ 0),
              NewBindAction(/* reuse */ false, /* device */ 0,
                            /* want */ EADDRINUSE),
              NewBindAction(/* reuse */ true, /* device */ 0, /* want */ 0),
          }),
      NewSequenceTestCase(
          "binding with reuse and device",
          {
              NewBindAction(/* reuse */ true, /* device */ 123, /* want */ 0),
              NewBindAction(/* reuse */ false, /* device */ 123,
                            /* want */ EADDRINUSE),
              NewBindAction(/* reuse */ true, /* device */ 123, /* want */ 0),
              NewBindAction(/* reuse */ false, /* device */ 0,
                            /* want */ EADDRINUSE),
              NewBindAction(/* reuse */ true, /* device */ 456, /* want */ 0),
              NewBindAction(/* reuse */ true, /* device */ 0, /* want */ 0),
              NewBindAction(/* reuse */ true, /* device */ 789, /* want */ 0),
              NewBindAction(/* reuse */ false, /* device */ 999,
                            /* want */ EADDRINUSE),
          }),
      NewSequenceTestCase(
          "mixing reuse and not reuse by binding to device",
          {
              NewBindAction(/* reuse */ true, /* device */ 123, /* want */ 0),
              NewBindAction(/* reuse */ false, /* device */ 456, /* want */ 0),
              NewBindAction(/* reuse */ true, /* device */ 789, /* want */ 0),
              NewBindAction(/* reuse */ false, /* device */ 999, /* want */ 0),
          }),
      NewSequenceTestCase(
          "can't bind to 0 after mixing reuse and not reuse",
          {
              NewBindAction(/* reuse */ true, /* device */ 123, /* want */ 0),
              NewBindAction(/* reuse */ false, /* device */ 456, /* want */ 0),
              NewBindAction(/* reuse */ true, /* device */ 0,
                            /* want */ EADDRINUSE),
          }),
      NewSequenceTestCase(
          "bind and release",
          {
              NewBindAction(/* reuse */ true, /* device */ 123, /* want */ 0),
              NewBindAction(/* reuse */ true, /* device */ 0, /* want */ 0),
              NewBindAction(/* reuse */ false, /* device */ 345,
                            /* want */ EADDRINUSE),
              NewBindAction(/* reuse */ true, /* device */ 789, /* want */ 0),

              // Release the bind to device 0 and try again.
              NewReleaseAction(/* release_row */ 1),
              NewBindAction(/* reuse */ false, /* device */ 345, /* want */ 0),
          }),
      NewSequenceTestCase(
          "bind twice with reuse once",
          {
              NewBindAction(/* reuse */ false, /* device */ 123, /* want */ 0),
              NewBindAction(/* reuse */ true, /* device */ 0,
                            /* want */ EADDRINUSE),
          }),
  };
}

INSTANTIATE_TEST_SUITE_P(
    BindToDeviceTest, BindToDeviceSequenceTest,
    ::testing::Combine(::testing::Values(IPv4UDPUnboundSocket(0),
                                         IPv4TCPUnboundSocket(0)),
                       ::testing::ValuesIn(GetSequenceTestCases())));

INSTANTIATE_TEST_SUITE_P(BindToDeviceTest, BindToDeviceTest,
                         ::testing::Values(IPv4UDPUnboundSocket(0),
                                           IPv4TCPUnboundSocket(0)));

EndpointConfig NewEndpointConfig(std::string bind_to_device,
                                 double expected_ratio) {
  EndpointConfig endpoint_config;
  endpoint_config.bind_to_device = bind_to_device;
  endpoint_config.expected_ratio = expected_ratio;
  return endpoint_config;
}

DistributionTestCase NewDistributionTestCase(
    string name, std::vector<EndpointConfig> endpoints) {
  DistributionTestCase test_case;
  test_case.name = name;
  test_case.endpoints = endpoints;
  return test_case;
}

std::vector<DistributionTestCase> GetDistributionTestCases() {
  return std::vector<DistributionTestCase>{
      NewDistributionTestCase(
          "Even distribution among sockets not bound to device",
          {NewEndpointConfig("", 1. / 3), NewEndpointConfig("", 1. / 3),
           NewEndpointConfig("", 1. / 3)}),
      NewDistributionTestCase(
          "Sockets bound to other interfaces get no packets",
          {NewEndpointConfig("eth1", 0), NewEndpointConfig("", 1. / 2),
           NewEndpointConfig("", 1. / 2)}),
      NewDistributionTestCase(
          "Bound has priority over unbound",
          {NewEndpointConfig("eth1", 0), NewEndpointConfig("", 0),
           NewEndpointConfig("lo", 1)}),
      NewDistributionTestCase(
          "Even distribution among sockets bound to device",
          {NewEndpointConfig("eth1", 0), NewEndpointConfig("lo", 1. / 2),
           NewEndpointConfig("lo", 1. / 2)}),
  };
}

INSTANTIATE_TEST_SUITE_P(
    BindToDeviceTest, BindToDeviceDistributionTest,
    ::testing::Combine(::testing::Values(
                           // Listeners bound to IPv4 addresses refuse
                           // connections using IPv6 addresses.
                           ListenerConnector{V4Any(), V4Loopback()},
                           ListenerConnector{V4Loopback(), V4MappedLoopback()}),
                       ::testing::ValuesIn(GetDistributionTestCases())));

}  // namespace testing
}  // namespace gvisor
