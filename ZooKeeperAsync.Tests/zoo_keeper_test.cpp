#include "stdafx.h"
#include "client_base.hpp"

using namespace zoo;
using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace ZooKeeperAsyncTests
{
	TEST_CLASS(ZooKeeperTest)
	{
	public:
		std::future<void> DeleteRecursiveTestAsync()
		{
			zookeeper zk("127.0.0.1:2181", 3000);
			co_await zk.set_acl_async("/", OPEN_ACL_UNSAFE, -1);
			co_await client_base::delete_recursive_async(zk, "/a");

			co_await zk.set_data_async("/", "some", 4);
			co_await zk.create_async("/a", "some", 4, OPEN_ACL_UNSAFE, 0);
			co_await zk.create_async("/a/b", "some", 4, OPEN_ACL_UNSAFE, 0);
			co_await zk.create_async("/a/b/v", "some", 4, OPEN_ACL_UNSAFE, 0);
			co_await zk.create_async("/a/b/v/1", "some", 4, OPEN_ACL_UNSAFE, 0);
			co_await zk.create_async("/a/c", "some", 4, OPEN_ACL_UNSAFE, 0);
			co_await zk.create_async("/a/c/v", "some", 4, OPEN_ACL_UNSAFE, 0);

			auto res = co_await zk.get_children_async("/a");
			auto bResult = std::find(res.children.begin(), res.children.end(), "b");
			if (bResult == res.children.end())
				throw std::runtime_error("b not found");
			auto cResult = std::find(res.children.begin(), res.children.end(), "c");
			if (cResult == res.children.end())
				throw std::runtime_error("c not found");

			co_await client_base::delete_recursive_async(zk, "/a");
			auto existsAfterResult = co_await zk.exists_async("/a");
			if (existsAfterResult.has_value())
				throw std::runtime_error("node still exists after delete");
		}

		TEST_METHOD(DeleteRecursiveTest)
		{
			auto f = DeleteRecursiveTestAsync();
			f.wait();
			f.get();
		}
	};
}
