#include "stdafx.h"
#include "CppUnitTest.h"

#include "client_base.hpp"

using namespace zoo;
using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace ZooKeeperAsyncTests
{		
	TEST_CLASS(AclCountTest)
	{
	public:
		std::future<void> TestAclCountAsync()
		{
			const std::vector<ZkAcl> CREATOR_ALL_AND_WORLD_READABLE =
			{
				{ PERM_READ, "world", "anyone" },
				{ PERM_ALL, "auth", "" },
				{ PERM_READ, "world", "anyone" },
				{ PERM_ALL, "auth", "" },
			};

			// TODO: generic createClient();
			zookeeper zk("127.0.0.1:2181", 4000);

			const char * cert = "pat:test";
			co_await zk.add_auth_async("digest", cert, strlen(cert));
			co_await client_base::delete_recursive_async(zk, "/path");

			co_await zk.set_acl_async("/", CREATOR_ALL_ACL, -1);
			const char * value = "/path";
			co_await zk.create_async("/path", value, strlen(value), CREATOR_ALL_AND_WORLD_READABLE, ZOO_PERSISTENT);
			auto acls = (co_await zk.get_acl_async("/path"));
			Assert::AreEqual((size_t)2, std::get<0>(acls).size());

			co_await zk.set_acl_async("/", OPEN_ACL_UNSAFE, -1);
			co_await zk.set_acl_async("/path", OPEN_ACL_UNSAFE, -1);
			co_await client_base::delete_recursive_async(zk, "/path");
		}

		TEST_METHOD(TestAclCount)
		{
			auto f = TestAclCountAsync();
			f.wait();
			f.get();
		}
	};
}