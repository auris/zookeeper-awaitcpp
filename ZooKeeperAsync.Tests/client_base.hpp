#pragma once

#include "stdafx.h"

using namespace zoo;

class client_base
{
private:
	static std::future<std::vector<std::string> > list_subtree_bfs(zookeeper & zk, const std::string & pathRoot)
	{
		std::queue<std::string> queue;
		std::vector<std::string> tree;
		queue.push(pathRoot);
		tree.push_back(pathRoot);
		while (true)
		{
			if (queue.empty())
			{
				break;
			}
			auto node = queue.front();
			queue.pop();
			auto children = co_await zk.get_children_async(node.c_str());
			for (auto child : children.children)
			{
				auto childPath = node + "/" + child;
				queue.push(childPath);
				tree.push_back(childPath);
			}
		}
		return tree;
	}

public:
	static std::future<void> delete_recursive_async(zookeeper & zk, const std::string & pathRoot)
	{
		auto exists = co_await zk.exists_async(pathRoot.c_str());
		if (!exists.has_value())
			return;
		auto tree = co_await list_subtree_bfs(zk, pathRoot);

		zk_transaction tx;
		for (int i = (int)tree.size() - 1; i >= 0; --i)
		{
			// Delete the leaves first and eventually get rid of the root
			tx.delete_op(tree[i].c_str()); // Delete all versions of the node with -1.
		}
		co_await zk.multi_async(tx);
	}

	/*
	protected zookeeper createClient(Watcher watcher, string chroot = null, int timeout = CONNECTION_TIMEOUT)
	{
		if (watcher == null) watcher = NullWatcher.Instance;
		zookeeper zk(hostPort + m_currentRoot + chroot, timeout, watcher);
		if (!await zk.connectedSignal.Task.WithTimeout(timeout)) {
			Assert.fail("Unable to connect to server");
		}

		return zk;
	}
	*/
};
