#include "stdafx.h"
#include "CppUnitTest.h"

#include "client_base.hpp"

using namespace zoo;
using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace ZooKeeperAsyncTests
{
	TEST_CLASS(AclRootTest)
	{
	public:
		std::future<void> TestRootAclAsync()
		{
			{
				// TODO: generic createClient();
				zookeeper zk("127.0.0.1:2181", 4000);
				const char * cert = "pat:test";
				co_await zk.add_auth_async("digest", cert, strlen(cert));
				co_await zk.set_acl_async("/", CREATOR_ALL_ACL);
				co_await zk.get_data_async("/");
				zk.close();
			}

			{
				// TODO: generic createClient();
				zookeeper zk("127.0.0.1:2181", 4000);
				try
				{
					co_await zk.get_data_async("/");
					Assert::Fail(L"validate auth");
				}
				catch (const zk_error & error)
				{
					Assert::IsTrue(NO_AUTH == error.get_code());
				}

				try
				{
					co_await zk.create_async("/apps", nullptr, 0, CREATOR_ALL_ACL, ZOO_PERSISTENT);
					Assert::Fail(L"validate auth");
				}
				catch (const zk_error & error)
				{
					Assert::IsTrue(INVALID_ACL == error.get_code());
				}

				const char * cert = "world:anyone";
				co_await zk.add_auth_async("digest", cert, strlen(cert));
				try
				{
					await zk.create_async("/apps", nullptr, 0, CREATOR_ALL_ACL, ZOO_PERSISTENT);
					Assert::Fail(L"validate auth");
				}
				catch (const zk_error & error)
				{
					Assert::IsTrue(NO_AUTH == error.get_code());
				}
				zk.close();
			}

			{
				// TODO: generic createClient();
				zookeeper zk("127.0.0.1:2181", 4000);

				const char * cert = "pat:test";
				co_await zk.add_auth_async("digest", cert, strlen(cert));
				co_await zk.get_data_async("/");
				co_await zk.create_async("/apps", nullptr, 0, CREATOR_ALL_ACL, ZOO_PERSISTENT);
				co_await zk.delete_async("/apps", -1);
				// reset acl (back to open) and verify accessible again
				co_await zk.set_acl_async("/", OPEN_ACL_UNSAFE, -1);
			}

			{
				// TODO: generic createClient();
				zookeeper zk("127.0.0.1:2181", 4000);

				co_await zk.get_data_async("/");
				co_await zk.create_async("/apps", nullptr, 0, OPEN_ACL_UNSAFE, ZOO_PERSISTENT);
				try
				{
					await zk.create_async("/apps", nullptr, 0, CREATOR_ALL_ACL, ZOO_PERSISTENT);
					Assert::Fail(L"validate auth");
				}
				catch (const zk_error & error)
				{
					Assert::IsTrue(INVALID_ACL == error.get_code());
				}
				co_await zk.delete_async("/apps", -1);
				const char * cert = "world:anyone";
				co_await zk.add_auth_async("digest", cert, strlen(cert));
				co_await zk.create_async("/apps", nullptr, 0, CREATOR_ALL_ACL, ZOO_PERSISTENT);
			}

			{
				// TODO: generic createClient();
				zookeeper zk("127.0.0.1:2181", 4000);

				co_await zk.delete_async("/apps", -1);
			}
		}

		TEST_METHOD(TestRootAcl)
		{
			auto f = TestRootAclAsync();
			f.wait();
			f.get();
		}
	};
}