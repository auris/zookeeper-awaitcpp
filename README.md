# zookeeper-awaitcpp
ZooKeeper asynchronous C++ API taking advantage of co_await syntax.

co_await is supported in Visual Studio and clang (currently only trunk) and enables to write asynchronous code with significantly less boilerplane while providing zero overhead.

## Using
In order to use the zookeeper-awaitcpp library, #include <zookeeper/async_zookeeper.hpp> file found in include directory. Note that it is a wrapper on top of C zookeeper API and requires zookeeper.h to be available in include path, and also to link the zookeeper library (zookeeper_mt).

For example how to use, please see the unit tests directory ZooKeeperAsync.Tests.

## Unit tests
Some unit tests are ported from C#. They can be run only from Visual Studio at the moment. ZooKeeper server has to be running and accessible on default port.
