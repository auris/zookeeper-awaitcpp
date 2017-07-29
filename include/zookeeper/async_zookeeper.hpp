/**
* Licensed to the Apache Software Foundation (ASF) under one
* or more contributor license agreements.  See the NOTICE file
* distributed with this work for additional information
* regarding copyright ownership.  The ASF licenses this file
* to you under the Apache License, Version 2.0 (the
* "License"); you may not use this file except in compliance
* with the License.  You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

#ifndef ASYNC_ZOOKEEPER_H_INCLUDED
#define ASYNC_ZOOKEEPER_H_INCLUDED

#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <cerrno>

#include <exception>
#include <string>
#include <list>
#include <vector>
#include <functional>
#include <optional>

#include <experimental/coroutine>

/**
 * \file async_zookeeper.h
 */

/**
* \mainpage
* \brief ZooKeeper functions and definitions.
*
* ZooKeeper is a network service that may be backed by a cluster of
* synchronized servers. The data in the service is represented as a tree
* of data nodes. Each node has data, children, an ACL, and status information.
* The data for a node is read and write in its entirety.
*
* ZooKeeper clients can leave watches when they queries the data or children
* of a node. If a watch is left, that client will be notified of the change.
* The notification is a one time trigger. Subsequent chances to the node will
* not trigger a notification unless the client issues a query with the watch
* flag set. If the client is ever disconnected from the service, the watches do
* not need to be reset. The client automatically resets the watches.
*
* When a node is created, it may be flagged as an ephemeral node. Ephemeral
* nodes are automatically removed when a client session is closed or when
* a session times out due to inactivity (the ZooKeeper runtime fills in
* periods of inactivity with pings). Ephemeral nodes cannot have children.
*
* ZooKeeper clients are identified by a server assigned session id. For
* security reasons The server
* also generates a corresponding password for a session. A client may save its
* id and corresponding password to persistent storage in order to use the
* session across program invocation boundaries.
*/

namespace zoo
{
	using std::experimental::coroutine_handle;

	struct ZkStat
	{
		int64_t czxid;
		int64_t mzxid;
		int64_t ctime;
		int64_t mtime;
		int32_t version;
		int32_t cversion;
		int32_t aversion;
		int64_t ephemeralOwner;
		int32_t dataLength;
		int32_t numChildren;
		int64_t pzxid;
	};

	struct ZkAcl
	{
		int32_t permissions;
		std::string scheme;
		std::string id;

		ZkAcl(int32_t permissions, std::string scheme, std::string id)
			: permissions(permissions), scheme(std::move(scheme)), id(std::move(id))
		{
		}
	};


	/** \cond INTERNAL */
	namespace internal
	{
#ifdef WIN32
		#include <zookeeper.h>
#else
		#include <zookeeper/zookeeper.h>
#endif

		class zk_multi_future;

		const ZkAcl OPEN_ACL_UNSAFE_ACL = { 0x1f, "world", "anyone" };
		const ZkAcl READ_ACL_UNSAFE_ACL = { 0x01, "world", "anyone" };
		const ZkAcl CREATOR_ALL_ACL_ACL = { 0x1f, "auth", "" };
	}
	/** \endcond */

	/**
	* @name ACL Consts
	*/
	const int PERM_READ = 1 << 0;
	const int PERM_WRITE = 1 << 1;
	const int PERM_CREATE = 1 << 2;
	const int PERM_DELETE = 1 << 3;
	const int PERM_ADMIN = 1 << 4;
	const int PERM_ALL = 0x1f;

	/// This is a completely open ACL
	const std::vector<ZkAcl> OPEN_ACL_UNSAFE = { internal::OPEN_ACL_UNSAFE_ACL };

	/// This ACL gives the world the ability to read.
	const std::vector<ZkAcl> READ_ACL_UNSAFE = { internal::READ_ACL_UNSAFE_ACL };

	/// This ACL gives the creators authentication id's all permissions.
	const std::vector<ZkAcl> CREATOR_ALL_ACL = { internal::CREATOR_ALL_ACL_ACL };

	/**
	* @name Create Flags
	*
	* These flags are used by zoo_create to affect node create. They may
	* be ORed together to combine effects.
	*/
	// @{
	const int ZOO_PERSISTENT = 0;
	const int ZOO_EPHEMERAL = 1 << 0;
	const int ZOO_SEQUENCE = 1 << 1;
	// @}


	/**
	* @name State Consts
	* These constants represent the states of a zookeeper connection. They are
	* possible parameters of the watcher callback.
	*/
	// @{
	const int ZOO_EXPIRED_SESSION_STATE = -112;
	const int ZOO_AUTH_FAILED_STATE = -113;
	const int ZOO_CONNECTING_STATE = 1;
	const int ZOO_ASSOCIATING_STATE = 2;
	const int ZOO_CONNECTED_STATE = 3;
	// @}

	/// Codes which represent the various zk_error types.
	enum zk_error_code
	{
		/// Everything is OK
		OK = 0,

		// System and server-side errors.
		// This is never thrown by the server, it shouldn't be used other than
		// to indicate a range. Specifically error codes greater than this
		// value, but lesser than {@link #APIERROR}, are system errors.
		SYSTEM_ERROR = -1,

		/// <summary> A runtime inconsistency was found </summary> 
		RUNTIME_INCONSISTENCY = -2,
		/// <summary> A data inconsistency was found </summary> 
		DATA_INCONSISTENCY = -3,
		/// <summary> Connection to the server has been lost </summary> 
		CONNECTION_LOSS = -4,
		/// <summary> Error while marshalling or unmarshalling data </summary> 
		MARSHALLING_ERROR = -5,
		/// <summary> Operation is unimplemented </summary> 
		UNIMPLEMENTED = -6,
		/// <summary> Operation timeout </summary> 
		OPERATION_TIMEOUT = -7,
		/// <summary>Invalid arguments </summary> 
		BAD_ARGUMENTS = -8,
		/// <summary>Invalid state handle</summary> 
		INVALID_STATE = -9,

		/// <summary>Range of API errors</summary>
		/// <remarks>
		/// This is never thrown by the server, it shouldn't be used other than
		/// to indicate a range. Specifically error codes greater than this
		/// value are API errors (while values less than this indicate a
		/// {@link #SYSTEM_ERROR}).
		/// </remarks>
		API_ERROR = -100,

		/// <summary> Node does not exist </summary> 
		NO_NODE = -101,
		/// <summary> Not authenticated </summary> 
		NO_AUTH = -102,
		/// <summary> Version conflict </summary> 
		BAD_VERSION = -103,
		/// <summary> Ephemeral nodes may not have children </summary> 
		NO_CHILDREN_FOR_EPHEMERALS = -108,
		/// <summary> The node already exists </summary> 
		NODE_EXISTS = -110,
		/// <summary> The node has children </summary> 
		NOT_EMPTY = -111,
		/// <summary> The session has been expired by the server </summary> 
		SESSION_EXPIRED = -112,
		/// <summary> Invalid callback specified </summary> 
		INVALID_CALLBACK = -113,
		/// <summary> Invalid ACL specified </summary> 
		INVALID_ACL = -114,
		/// <summary> Client authentication failed </summary> 
		AUTH_FAILED = -115,
		/// <summary> Session moved to another server, so operation is ignored </summary> 
		SESSION_MOVED = -118,

		/// <summary> State-changing request is passed to read-only server </summary>
		NOT_READONLY = -119
	};

	class zk_error : public std::exception
	{
	private:
		zk_error_code m_code;
		const char * m_what;
		const char * m_path;

	public:
		zk_error(zk_error_code code, const char * path = nullptr)
			: m_what(code_to_message(code)), m_code(code), m_path(path)
		{
		}

		const char * what() const noexcept override
		{
			return m_what;
		}

		static void check(int rc, const char * path = nullptr)
		{
			zk_error_code code = (zk_error_code)rc;
			if (code != OK)
				throw zk_error(code, path);
		}

		zk_error_code get_code() const
		{
			return m_code;
		}

		std::string get_path() const
		{
			return std::string(m_path);
		}

		static const char * code_to_message(zk_error_code code)
		{
			switch (code)
			{
			case OK:
				return "Everything is OK";
			case RUNTIME_INCONSISTENCY:
				return "A runtime inconsistency was found";
			case DATA_INCONSISTENCY:
				return "A data inconsistency was found";
			case CONNECTION_LOSS:
				return "Connection to the server has been lost";
			case MARSHALLING_ERROR:
				return "Error while marshalling or unmarshalling data";
			case UNIMPLEMENTED:
				return "Operation is unimplemented";
			case OPERATION_TIMEOUT:
				return "Operation timeout";
			case BAD_ARGUMENTS:
				return "Invalid arguments";
			case NO_NODE:
				return "Node does not exist";
			case NO_AUTH:
				return "Not authenticated";
			case BAD_VERSION:
				return "Version conflict";
			case NO_CHILDREN_FOR_EPHEMERALS:
				return "Ephemeral nodes may not have children";
			case NODE_EXISTS:
				return "The node already exists";
			case NOT_EMPTY:
				return "The node has children";
			case SESSION_EXPIRED:
				return "The session has been expired by the server";
			case INVALID_CALLBACK:
				return "Invalid callback specified";
			case INVALID_ACL:
				return "Invalid ACL specified";
			case AUTH_FAILED:
				return "Client authentication failed";
			case SESSION_MOVED:
				return "Session moved to another server, so operation is ignored";
			case NOT_READONLY:
				return "State-changing request is passed to read-only server";
			default:
				return "Unknown";
			}
		}
	};

	class zk_op_result
	{
	public:
		int err;
		std::string value;
		internal::Stat stat;
	};


	typedef std::function<void(int type, int state, const char * path)> zk_watcher_callback;

	class zk_children_result
	{
	public:
		std::vector<std::string> children;
		internal::Stat stat;
	};

	class zk_transaction
	{
	protected:
		struct zk_op
		{
			int type;
			std::string path;
			std::string value;
			std::vector<ZkAcl> acl;
			int flags;
			int version;
		};
		std::list<zk_op> m_ops;


		friend class internal::zk_multi_future;
	public:
		void create_op(const char * path, const void * value, size_t valueSize, const std::vector<ZkAcl> & acl, int flags)
		{
			// TODO: validate path
			m_ops.emplace_back();
			zk_op & op = m_ops.back();
			op.type = ZOO_CREATE_OP;
			op.path = path;
			op.value = std::string((const char *)value, (int)valueSize);
			op.acl = acl;
			op.flags = flags;
		}

		void delete_op(const char * path, int version = -1)
		{
			m_ops.emplace_back();
			zk_op & op = m_ops.back();
			op.type = ZOO_DELETE_OP;
			op.path = path;
			op.version = version;
		}

		void set_op(const char * path, const void * data, size_t dataSize, int version = -1)
		{
			m_ops.emplace_back();
			zk_op & op = m_ops.back();
			op.type = ZOO_SETDATA_OP;
			op.path = path;
			op.value = std::string((const char *)data, (int)dataSize);
			op.version = version;
		}

		void check_op(const char * path, int version = -1)
		{
			m_ops.emplace_back();
			zk_op & op = m_ops.back();
			op.type = ZOO_CHECK_OP;
			op.path = path;
			op.version = version;
		}
	};

	/** \cond INTERNAL */
	namespace internal
	{
		inline std::vector<internal::ACL> toInternalAcl(const std::vector<ZkAcl> & acl)
		{
			std::vector<internal::ACL> aclValues(acl.size());
			for (size_t i = 0; i < acl.size(); i++)
			{
				aclValues[i].perms = acl[i].permissions;
				aclValues[i].id.scheme = const_cast<char *>(acl[i].scheme.c_str());
				aclValues[i].id.id = const_cast<char *>(acl[i].id.c_str());
			}
			return aclValues;
		}


		class zk_exists_future
		{
		private:
			zhandle_t * m_handle;
			const char * m_path;
			int m_watch;
			zk_watcher_callback m_watcher;
			void * m_coroutine;
			int m_rc;
			Stat m_stat;

		public:
			zk_exists_future(zhandle_t * handle, const char * path, bool watch)
				: m_handle(handle), m_path(path), m_watch(watch), m_watcher(nullptr), m_coroutine(nullptr), m_rc(-1), m_stat()
			{
			}

			zk_exists_future(zhandle_t * handle, const char * path, zk_watcher_callback watcher)
				: m_handle(handle), m_path(path), m_watch(false), m_watcher(std::move(watcher)), m_coroutine(nullptr), m_rc(-1), m_stat()
			{
			}


			bool await_ready()
			{
				return false;
			}

			void await_suspend(coroutine_handle<> ch)
			{
				m_coroutine = ch.address();
				stat_completion_t statCompletion = [](int rc, const struct Stat * stat, const void * data)
				{
					zk_exists_future * self = static_cast<zk_exists_future *>(const_cast<void *>(data));
					auto cr = coroutine_handle<>::from_address(self->m_coroutine);
					self->m_rc = rc;
					if (stat)
						self->m_stat = *stat;
					cr.resume();
				};
				if (m_watcher)
				{

					int rc = zoo_awexists(m_handle, m_path,
						[](zhandle_t *zh, int type, int state, const char *path, void *watcherCtx)
					{
						zk_exists_future * self = static_cast<zk_exists_future *>(const_cast<void *>(watcherCtx));
						self->m_watcher(type, state, path);
					},
						this, statCompletion, this);
					zk_error::check(rc, m_path);
				}
				else
				{
					int rc = zoo_aexists(m_handle, m_path, m_watch, statCompletion, this);
					zk_error::check(rc, m_path);
				}
			}

			std::optional<Stat> await_resume()
			{
				if (m_rc == NO_NODE)
					return {};
				zk_error::check(m_rc, m_path);
				if (m_stat.czxid == -1)
					return {};
				return m_stat;
			}
		};

		class zk_get_data_future
		{
		private:
			zhandle_t * m_handle;
			std::string m_path;
			zk_watcher_callback m_watcher;
			void * m_coroutine;
			int m_rc;
			std::string m_value;
			Stat m_stat;

		public:
			zk_get_data_future(zhandle_t * handle, std::string path, zk_watcher_callback watcher)
				: m_handle(handle), m_path(std::move(path)), m_watcher(std::move(watcher)), m_coroutine(nullptr), m_rc(-1), m_stat()
			{
			}


			bool await_ready()
			{
				return false;
			}

			void await_suspend(coroutine_handle<> ch)
			{
				m_coroutine = ch.address();
				data_completion_t completion = [](int rc, const char * value, int valueSize, const struct Stat * stat, const void * data)
				{
					zk_get_data_future * self = static_cast<zk_get_data_future *>(const_cast<void *>(data));
					auto cr = coroutine_handle<>::from_address(self->m_coroutine);
					self->m_rc = rc;
					if (value)
						self->m_value = std::string(value, valueSize);
					if (stat)
						self->m_stat = *stat;
					cr.resume();
				};
				watcher_fn watcher = [](zhandle_t *zh, int type, int state, const char *path, void *watcherCtx)
				{
					zk_get_data_future * self = static_cast<zk_get_data_future *>(const_cast<void *>(watcherCtx));
					self->m_watcher(type, state, path);
				};
				int rc = zoo_awget(m_handle, m_path.c_str(),
					m_watcher ? watcher : nullptr, this, completion, this);
				zk_error::check(rc, m_path.c_str());
			}

			std::tuple<std::string, Stat> await_resume()
			{
				zk_error::check(m_rc, m_path.c_str());
				return std::make_tuple(m_value,  m_stat);
			}
		};

		class zk_create_future
		{
		private:
			zhandle_t * m_handle;
			const char * m_path;
			const void * m_value;
			size_t m_valueSize;
			std::vector<internal::ACL> m_acl;
			int m_flags;
			void * m_coroutine;
			int m_rc;
			std::string m_result;

		public:
			zk_create_future(zhandle_t * handle, const char * path, const void * value, size_t valueSize, const std::vector<ZkAcl> & aclEntries, int flags)
				: m_handle(handle), m_path(path), m_value(value), m_valueSize(valueSize), m_acl(toInternalAcl(aclEntries)), m_flags(flags), m_coroutine(nullptr), m_rc(-1)
			{
			}

			bool await_ready()
			{
				return false;
			}

			void await_suspend(coroutine_handle<> ch)
			{
				m_coroutine = ch.address();
				string_completion_t stringCompletion = [](int rc, const char *value, const void *data)
				{
					zk_create_future * self = static_cast<zk_create_future *>(const_cast<void *>(data));
					auto cr = coroutine_handle<>::from_address(self->m_coroutine);
					self->m_rc = rc;
					if (value)
						self->m_result = value;
					cr.resume();
				};
				ACL_vector aclVec = { (int)m_acl.size(), &m_acl[0] };
				int rc = zoo_acreate(m_handle, m_path, (const char *)m_value, (int)m_valueSize,
					&aclVec, m_flags, stringCompletion, this);
				zk_error::check(rc, m_path);
			}

			std::string await_resume()
			{
				zk_error::check(m_rc, m_path);
				return m_result;
			}
		};

		class zk_delete_future
		{
		private:
			zhandle_t * m_handle;
			const char * m_path;
			int m_version;
			void * m_coroutine;
			int m_rc;

		public:
			zk_delete_future(zhandle_t * handle, const char * path, int version)
				: m_handle(handle), m_path(path), m_version(version), m_coroutine(nullptr), m_rc(-1)
			{
			}

			bool await_ready()
			{
				return false;
			}

			void await_suspend(coroutine_handle<> ch)
			{
				m_coroutine = ch.address();
				auto completion = [](int rc, const void * data)
				{
					zk_delete_future * self = static_cast<zk_delete_future *>(const_cast<void *>(data));
					auto cr = coroutine_handle<>::from_address(self->m_coroutine);
					self->m_rc = rc;
					cr.resume();
				};
				int rc = zoo_adelete(m_handle, m_path, m_version, completion, this);
				zk_error::check(rc, m_path);
			}

			void await_resume()
			{
				zk_error::check(m_rc, m_path);
			}
		};

		class zk_set_future
		{
		private:
			zhandle_t * m_handle;
			const char * m_path;
			const void * m_value;
			size_t m_valueSize;
			int m_version;
			void * m_coroutine;
			int m_rc;
			Stat m_result;

		public:
			zk_set_future(zhandle_t * handle, const char * path, const void * value, size_t valueSize, int version)
				: m_handle(handle), m_path(path), m_value(value), m_valueSize(valueSize), m_version(version), m_coroutine(nullptr), m_rc(-1), m_result()
			{
			}

			bool await_ready()
			{
				return false;
			}

			void await_suspend(coroutine_handle<> ch)
			{
				m_coroutine = ch.address();
				stat_completion_t statCompletion = [](int rc, const struct Stat * stat, const void * data)
				{
					zk_set_future * self = static_cast<zk_set_future *>(const_cast<void *>(data));
					auto cr = coroutine_handle<>::from_address(self->m_coroutine);
					self->m_rc = rc;
					if (stat)
						self->m_result = *stat;
					cr.resume();
				};
				int rc = zoo_aset(m_handle, m_path, (const char *)m_value, (int)m_valueSize, m_version, statCompletion, this);
				zk_error::check(rc, m_path);
			}

			Stat await_resume()
			{
				zk_error::check(m_rc, m_path);
				return m_result;
			}
		};

		class zk_get_children_future
		{
		private:
			zhandle_t * m_handle;
			const char * m_path;
			int m_watch;
			zk_watcher_callback m_watcher;
			void * m_coroutine;
			int m_rc;
			zk_children_result m_result;

		public:
			zk_get_children_future(zhandle_t * handle, const char * path, bool watch)
				: m_handle(handle), m_path(path), m_watch(watch), m_watcher(nullptr), m_coroutine(nullptr), m_rc(-1), m_result()
			{
			}

			zk_get_children_future(zhandle_t * handle, const char * path, zk_watcher_callback watcher)
				: m_handle(handle), m_path(path), m_watch(false), m_watcher(std::move(watcher)), m_coroutine(nullptr), m_rc(-1), m_result()
			{
			}


			bool await_ready()
			{
				return false;
			}

			void await_suspend(coroutine_handle<> ch)
			{
				m_coroutine = ch.address();
				strings_stat_completion_t completion = [](int rc, const struct String_vector *strings, const struct Stat *stat, const void *data)
				{
					zk_get_children_future * self = static_cast<zk_get_children_future *>(const_cast<void *>(data));
					auto cr = coroutine_handle<>::from_address(self->m_coroutine);
					self->m_rc = rc;
					if (rc == 0 && strings)
					{
						auto& children = self->m_result.children;
						children.reserve(strings->count);
						for (int i = 0; i < strings->count; i++)
						{
							children.emplace_back(strings->data[i]);
						}
					}
					if (rc == 0 && stat)
					{
						self->m_result.stat = *stat;
					}
					cr.resume();
				};
				if (m_watcher)
				{

					int rc = zoo_awget_children2(m_handle, m_path,
						[](zhandle_t *zh, int type, int state, const char *path, void *watcherCtx)
					{
						zk_get_children_future * self = static_cast<zk_get_children_future *>(const_cast<void *>(watcherCtx));
						self->m_watcher(type, state, path);
					},
						this, completion, this);
					zk_error::check(rc, m_path);
				}
				else
				{
					int rc = zoo_aget_children2(m_handle, m_path, m_watch, completion, this);
					zk_error::check(rc, m_path);
				}
			}

			zk_children_result await_resume()
			{
				zk_error::check(m_rc, m_path);
				return m_result;
			}
		};

		class zk_multi_future
		{
		private:
			struct zk_op_out_values
			{
				char * pathBuffer;
				int pathBufferLength;
				Stat stat;
			};

			zhandle_t * m_handle;
			std::vector<zoo_op_t> m_ops;
			std::vector<zoo_op_result_t> m_opResults;
			//std::vector<zk_op_out_values> m_opOutValues;
			void * m_coroutine;
			int m_rc;

		public:
			zk_multi_future(zhandle_t * handle, const zk_transaction & tx)
				: m_handle(handle),
				m_ops(tx.m_ops.size()),
				m_opResults(tx.m_ops.size()),
				//m_opOutValues(tx.m_ops.size()),
				m_coroutine(nullptr),
				m_rc(-1)
			{
				int i = 0;
				for (const auto& op : tx.m_ops)
				{
					switch (op.type)
					{
					case ZOO_CREATE_OP:
						zoo_create_op_init(&m_ops[i], op.path.c_str(), op.value.c_str(), (int)op.value.size(),
							&internal::ZOO_OPEN_ACL_UNSAFE, op.flags,
							nullptr, 0);
						// TODO: out path.
						break;
					case ZOO_DELETE_OP:
						zoo_delete_op_init(&m_ops[i], op.path.c_str(), op.version);
						break;
					case ZOO_SETDATA_OP:
						zoo_set_op_init(&m_ops[i], op.path.c_str(), op.value.c_str(), (int)op.value.size(), op.version, nullptr);
						// TODO: out stat
						break;
					case ZOO_CHECK_OP:
						zoo_check_op_init(&m_ops[i], op.path.c_str(), op.version);
						break;
					default:
						throw std::runtime_error("Not implemented");
					}
					i++;
				}
			}

			bool await_ready()
			{
				return false;
			}

			void await_suspend(coroutine_handle<> ch)
			{
				m_coroutine = ch.address();
				auto completion = [](int rc, const void * data)
				{
					zk_multi_future * self = static_cast<zk_multi_future *>(const_cast<void *>(data));
					auto cr = coroutine_handle<>::from_address(self->m_coroutine);
					self->m_rc = rc;
					cr.resume();
				};
				int rc = zoo_amulti(m_handle, (int)m_ops.size(), &m_ops[0], &m_opResults[0], completion, this);
				zk_error::check(rc);
			}

			std::vector<zoo_op_result_t> await_resume()
			{
				zk_error::check(m_rc);
				return m_opResults;
			}
		};

		class zk_flush_future
		{
		private:
			zhandle_t * m_handle;
			void * m_coroutine;
			const char * m_path;
			int m_rc;
			std::string m_result;

		public:
			zk_flush_future(zhandle_t * handle, const char * path)
				: m_handle(handle),
				m_path(path),
				m_coroutine(nullptr),
				m_rc(-1)
			{
			}

			bool await_ready()
			{
				return false;
			}

			void await_suspend(coroutine_handle<> ch)
			{
				m_coroutine = ch.address();
				auto completion = [](int rc, const char * result, const void * data)
				{
					zk_flush_future * self = static_cast<zk_flush_future *>(const_cast<void *>(data));
					auto cr = coroutine_handle<>::from_address(self->m_coroutine);
					self->m_rc = rc;
					if (result)
						self->m_result = result;
					cr.resume();
				};
				int rc = zoo_async(m_handle, m_path, completion, this);
				zk_error::check(rc);
			}

			std::string await_resume()
			{
				zk_error::check(m_rc);
				return m_result;
			}
		};

		class zk_get_acl_future
		{
		private:
			zhandle_t * m_handle;
			void * m_coroutine;
			const char * m_path;
			int m_rc;
			ZkStat m_stat;
			std::vector<ZkAcl> m_acl;

		public:
			zk_get_acl_future(zhandle_t * handle, const char * path)
				: m_handle(handle),
				m_path(path),
				m_coroutine(nullptr),
				m_rc(-1)
			{
			}

			bool await_ready()
			{
				return false;
			}

			void await_suspend(coroutine_handle<> ch)
			{
				m_coroutine = ch.address();
				auto completion = [](int rc, struct ACL_vector *acl, struct Stat *stat, const void * data)
				{
					zk_get_acl_future * self = static_cast<zk_get_acl_future *>(const_cast<void *>(data));
					auto cr = coroutine_handle<>::from_address(self->m_coroutine);
					self->m_rc = rc;
					if (acl)
					{
						self->m_acl.reserve(acl->count);
						for (int i = 0; i < acl->count; i++)
						{
							const auto& a = acl->data[i];
							self->m_acl.emplace_back(a.perms, a.id.scheme, a.id.id);
						}
					}
					if (stat)
						memcpy(&self->m_stat, stat, sizeof(*stat));
					cr.resume();
				};
				int rc = zoo_aget_acl(m_handle, m_path, completion, this);
				zk_error::check(rc);
			}

			std::tuple<std::vector<ZkAcl>, ZkStat> await_resume()
			{
				zk_error::check(m_rc);
				return std::tuple<std::vector<ZkAcl>, ZkStat>(m_acl, m_stat);
			}
		};

		class zk_set_acl_future
		{
		private:
			zhandle_t * m_handle;
			void * m_coroutine;
			const char * m_path;
			std::vector<internal::ACL> m_acl;
			int m_version;
			int m_rc;

		public:
			zk_set_acl_future(zhandle_t * handle, const char * path, const std::vector<ZkAcl> & acl, int version)
				: m_handle(handle),
				m_path(path),
				m_acl(toInternalAcl(acl)),
				m_version(version),
				m_coroutine(nullptr),
				m_rc(-1)
			{
			}

			bool await_ready()
			{
				return false;
			}

			void await_suspend(coroutine_handle<> ch)
			{
				m_coroutine = ch.address();
				auto completion = [](int rc, const void * data)
				{
					zk_set_acl_future * self = static_cast<zk_set_acl_future *>(const_cast<void *>(data));
					auto cr = coroutine_handle<>::from_address(self->m_coroutine);
					self->m_rc = rc;
					cr.resume();
				};
				ACL_vector acl = { (int)m_acl.size(), &m_acl[0] };
				int rc = zoo_aset_acl(m_handle, m_path, m_version, &acl, completion, this);
				zk_error::check(rc);
			}

			void await_resume()
			{
				zk_error::check(m_rc);
			}
		};

		class zk_add_auth_future
		{
		private:
			zhandle_t * m_handle;
			::std::string m_schema;
			::std::string m_cert;
			void * m_coroutine;
			int m_rc;

		public:
			zk_add_auth_future(zhandle_t * handle, ::std::string schema, ::std::string cert)
				: m_handle(handle),
				m_schema(std::move(schema)),
				m_cert(std::move(cert)),
				m_coroutine(nullptr),
				m_rc(-1)
			{
			}

			bool await_ready()
			{
				return false;
			}

			void await_suspend(coroutine_handle<> ch)
			{
				m_coroutine = ch.address();
				auto completion = [](int rc, const void * data)
				{
					zk_add_auth_future * self = static_cast<zk_add_auth_future *>(const_cast<void *>(data));
					auto cr = coroutine_handle<>::from_address(self->m_coroutine);
					self->m_rc = rc;
					cr.resume();
				};
				int rc = zoo_add_auth(m_handle, m_schema.c_str(), m_cert.c_str(), (int)m_cert.size(), completion, this);
				zk_error::check(rc);
			}

			void await_resume()
			{
				zk_error::check(m_rc);
			}
		};
	}
	/** \endcond */

	/// <summary>
	/// This is the main class of ZooKeeper client library. To use a ZooKeeper
	/// service, an application must first instantiate an object of ZooKeeper class.
	/// All the iterations will be done by calling the methods of ZooKeeper class.
	/// The methods of this class are thread-safe unless otherwise noted.
	/// </summary>
	/// <remarks>
	/// Once a connection to a server is established, a session ID is assigned to the
	/// client. The client will send heart beats to the server periodically to keep
	/// the session valid.
	/// 
	/// The application can call ZooKeeper APIs through a client as long as the
	/// session ID of the client remains valid.
	/// 
	/// If for some reason, the client fails to send heart beats to the server for a
	/// prolonged period of time (exceeding the sessionTimeout value, for instance),
	/// the server will expire the session, and the session ID will become invalid.
	/// The client object will no longer be usable. To make ZooKeeper API calls, the
	/// application must create a new client object.
	/// 
	/// If the ZooKeeper server the client currently connects to fails or otherwise
	/// does not respond, the client will automatically try to connect to another
	/// server before its session ID expires. If successful, the application can
	/// continue to use the client.
	/// 
	/// The ZooKeeper API method are asynchronous. An awaitable object is returned which
	/// needs to be awaited using co_await operator.
	/// 
	/// Some successful ZooKeeper API calls can leave watches on the "data nodes" in
	/// the ZooKeeper server. Other successful ZooKeeper API calls can trigger those
	/// watches. Once a watch is triggered, an event will be delivered to the client
	/// which left the watch at the first place. Each watch can be triggered only
	/// once. Thus, up to one event will be delivered to a client for every watch it
	/// leaves.
	/// 
	/// A client needs an object of a class implementing Watcher interface for
	/// processing the events delivered to the client.
	///
	/// When a client drops current connection and re-connects to a server, all the
	/// existing watches are considered as being triggered but the undelivered events
	/// are lost. To emulate this, the client will generate a special event to tell
	/// the event handler a connection has been dropped. This special event has type
	/// EventNone and state sKeeperStateDisconnected
	/// </remarks>
	class zookeeper
	{
	private:
		using zhandle_t = internal::zhandle_t;
		zhandle_t * m_handle;
		zk_watcher_callback m_watcher;

		static void global_watcher_proc(zhandle_t* h, int type, int state, const char* path, void* ctx)
		{
			zookeeper * zk = static_cast<zookeeper *>(ctx);
			if (zk->m_watcher)
			{
				zk->m_watcher(type, state, path);
			}
		}

		/**
		* \brief validate the provided znode path string
		* \param path znode path string
		* \param is_sequential if the path is being created with a sequential flag
		* \exception std::invalid_argument if the path is invalid
		*/
		static void validate_path(const char * path, bool is_sequential)
		{
			validate_path(is_sequential ? (std::string(path) + "1").c_str() : path);
		}

		/**
		* \brief validate the provided znode path string
		* \param path znode path string
		* \exception std::invalid_argument if the path is invalid
		*/
		static void validate_path(const char * path)
		{
			if (path == nullptr)
			{
				throw std::invalid_argument("Path cannot be null");
			}
			size_t length = strlen(path);
			if (length == 0)
			{
				throw std::invalid_argument("Path length must be > 0");
			}
			if (path[0] != '/')
			{
				throw std::invalid_argument("Path must start with / character");
			}
			if (length == 1)
			{
				// done checking - it's the root
				return;
			}
			if (path[length - 1] == '/')
			{
				throw std::invalid_argument("Path must not end with / character");
			}

			std::string reason;
			char lastc = '/';
			char c;
			for (size_t i = 1; i < length; lastc = path[i], i++)
			{
				c = path[i];
				if (c == 0)
				{
					reason = "null character not allowed @" + std::to_string(i);
					break;
				}
				if (c == '/' && lastc == '/')
				{
					reason = "empty node name specified @" + std::to_string(i);
					break;
				}
				if (c == '.' && lastc == '.')
				{
					if (path[i - 2] == '/' && ((i + 1 == length) || path[i + 1] == '/'))
					{
						reason = "relative paths not allowed @" + std::to_string(i);
						break;
					}
				}
				else if (c == '.')
				{
					if (path[i - 1] == '/' && ((i + 1 == length) || path[i + 1] == '/'))
					{
						reason = "relative paths not allowed @" + std::to_string(i);
						break;
					}
				}
				else if ((c > '\x00' && c < '\x1f') || (c > '\x7f' && c < '\x9F'))
				{
					reason = "invalid charater @" + std::to_string(i);
					break;
				}
			}

			if (!reason.empty())
			{
				throw std::invalid_argument(std::string("Invalid path string \"") + path + "\" caused by " + reason);
			}
		}

	public:
		zookeeper(const char * hostname, int recv_timeout, const zk_watcher_callback & watcher = nullptr)
			: m_handle(nullptr), m_watcher(watcher)
		{
			// TODO: handle client id
			m_handle = zookeeper_init(hostname,
				global_watcher_proc,
				recv_timeout,
				nullptr, // client id
				this,
				0);
			if (m_handle == nullptr)
				throw zk_error((zk_error_code)errno);

		}

		~zookeeper()
		{
			if (m_handle)
			{
				zookeeper_close(m_handle);
			}
		}

		/// <summary>Close the zookeeper handle and free up any resources.</summary>
		/// <remarks>
		/// After this call, the client session will no longer be valid. The function
		/// will flush any outstanding send requests before return. As a result it may
		/// block.
		///
		/// Calling any other zookeeper method after calling close is undefined behaviour and should be avoided.
		/// </remarks>
		void close()
		{
			if (m_handle)
			{
				int rc = zookeeper_close(m_handle);
				zk_error::check(rc);
				m_handle = nullptr;
			}
		}

		// TODO: get client id?

		// TODO: get negotiated timeout.

		/// <summary>Get the state of the zookeeper connection</summary>
		/// <remarks>
		/// The return value will be one of the \ref State Consts.
		/// <remarks>
		int get_state() const
		{
			return zoo_state(m_handle);
		}

		/// <summary>Create a node.</summary>
		/// This method will create a node in ZooKeeper. A node can only be created if
		/// it does not already exists.The Create Flags affect the creation of nodes.
		/// If ZOO_EPHEMERAL flag is set, the node will automatically get removed if the
		/// client session goes away.If the ZOO_SEQUENCE flag is set, a unique
		/// monotonically increasing sequence number is appended to the path name.The
		/// sequence number is always fixed length of 10 digits, 0 padded.
		/// <param name="path">The name of the node. Expressed as a file name with slashes
		/// separating ancestors of the node.</param>
		/// <param name="value">The data to be stored in the node.</param>
		/// <param name="valueSize">The number of bytes in data.</param>
		/// <param name="acl">The initial ACL of the node.</param>
		/// <param name="flags">this parameter can be set to 0 for normal create or an OR
		/// of the Create Flags</param>
		/// <returns>std::string path of the created node</returns>
		/// <exception cref="zk_error">with one of the following codes:<list>
		/// <item><term>NO_NODE</term> <description>the parent node does not exist.</description></item>
		/// <item><term>NO_AUTH</term> <description> the client does not have permission.</description></item>
		/// <item><term>NO_CHILDREN_FOR_EPHEMERALS</term> <description>cannot create children of ephemeral nodes.</description></item>
		/// </list></exception>
		internal::zk_create_future create_async(const char * path, const void * value, size_t valueSize, const std::vector<ZkAcl> & acl, int flags)
		{
			validate_path(path);
			return internal::zk_create_future(m_handle, path, value, valueSize, acl, flags);
		}

		/// <summary>Delete a node in zookeeper.</summary>
		/// <param name="path">The name of the node. Expressed as a file name with slashes
		/// separating ancestors of the node.</param>
		/// <param name="version">the expected version of the node. The function will fail if the
		/// actual version of the node does not match the expected version.</param>
		/// <exception cref="zk_error">with one of the following codes:<list>
		/// <item><term>NO_NODE</term> <description>the node does not exist.</description></item>
		/// <item><term>NO_AUTH</term> <description>the client does not have permission.</description></item>
		/// <item><term>BAD_VERSION</term> <description>expected version does not match actual version.</description></item>
		/// <item><term>NOT_EMPTY</term> <description>children are present; node cannot be deleted.</description></item>
		/// </list></exception>
		internal::zk_delete_future delete_async(const char * path, int version = -1)
		{
			validate_path(path);
			return internal::zk_delete_future(m_handle, path, version);
		}

		/// <summary>
		/// Checks the existence of a node in zookeeper.
		/// </summary>
		/// <remarks>
		/// Return the stat of the node of the given path. Return null if no such a
		/// node exists.
		/// If the watch is true and the call is successful (no exception is thrown),
		/// a watch will be left on the node with the given path. The watch will be
		/// triggered by a successful operation that creates/delete the node or sets
		/// the data on the node.
		/// </remarks>
		/// <param name="path">the name of the node. Expressed as a file name with slashes separating ancestors of the node.</param>
		/// <param name="watcher">if non-null a watch will set on the specified znode on the server.
		/// The watch will be set even if the node does not exist. This allows clients
		/// to watch for nodes to appear.</param>
		/// <returns>a std::optional&ls;Stat&gt; which contains a value only the if node exists.</returns>
		internal::zk_exists_future exists_async(const char * path, const zk_watcher_callback & watcher = nullptr)
		{
			validate_path(path);
			return internal::zk_exists_future(m_handle, path, watcher);
		}

		/// <summary>Gets the data associated with a node.</summary>
		/// <param name="path">the name of the node. Expressed as a file name with slashes separating ancestors of the node.</param>
		/// <param name="watcher">if non-null a watch will set on the specified znode on the server.
		/// The watch will be set even if the node does not exist. This allows clients
		/// to watch for nodes to appear.</param>
		/// <returns>a std::tuple&lt;std::string, Stat&gt; which contains value of the node and stat</returns>
		internal::zk_get_data_future get_data_async(const char * path, const zk_watcher_callback & watcher = nullptr)
		{
			validate_path(path);
			return internal::zk_get_data_future(m_handle, path, watcher);
		}

		/// <summary>Sets the data associated with a node.</summary>
		/// <param name="path">the name of the node. Expressed as a file name with slashes separating ancestors of the node.</param>
		/// <param name="value">the buffer holding data to be written to the node.</param>
		/// <param name="valueSize">the number of bytes from buffer to write.</param>
		/// <param name="version">the expected version of the node. The function will fail if
		/// the actual version of the node does not match the expected version. If -1 is
		/// used the version check will not take place.</param>
		/// <exception cref="zk_error">with one of the following codes:<list>
		/// <item><term>NO_NODE</term> <description>the node does not exist.</description></item>
		/// <item><term>NO_AUTH</term> <description>the client does not have permission.</description></item>
		/// <item><term>BAD_VERSION</term> <description>expected version does not match actual version.</description></item>
		/// </list></exception>
		internal::zk_set_future set_data_async(const char * path, const void * value, size_t valueSize, int version = -1)
		{
			validate_path(path);
			return internal::zk_set_future(m_handle, path, value, valueSize, version);
		}

		/// <summary>Lists the children of a node, and get the parent stat.</summary>
		/// <param name="path">the name of the node. Expressed as a file name with slashes separating ancestors of the node.</param>
		/// <param name="watcher">if non-null, a watch will be set at the server to notify the client if the node changes.</param>
		/// <exception cref="zk_error">with one of the following codes:<list>
		/// <item><term>NO_NODE</term> <description>the node does not exist.</description></item>
		/// <item><term>NO_AUTH</term> <description>the client does not have permission.</description></item>
		/// </list></exception>
		internal::zk_get_children_future get_children_async(const char * path, const zk_watcher_callback & watcher = nullptr)
		{
			validate_path(path);
			return internal::zk_get_children_future(m_handle, path, watcher);
		}

		/// <summary>Flush leader channel.</summary>
		/// <param name="path">the name of the node. Expressed as a file name with slashes separating ancestors of the node.</param>
		/// <exception cref="zk_error">with one of the following codes:<list>
		/// <item><term>NO_NODE</term> <description>the node does not exist.</description></item>
		/// <item><term>NO_AUTH</term> <description>the client does not have permission.</description></item>
		/// </list></exception>
		internal::zk_flush_future flush_async(const char * path)
		{
			validate_path(path);
			return internal::zk_flush_future(m_handle, path);
		}

		/// <summary>Gets the ACL associated with a node.</summary>
		/// <param name="path">the name of the node. Expressed as a file name with slashes separating ancestors of the node.</param>
		/// <returns>std::tuple&lt;zk_acl_vector, Stat&gt;</returns>
		/// <exception cref="zk_error">with one of the following codes:<list>
		/// <item><term>NO_NODE</term> <description>the node does not exist.</description></item>
		/// <item><term>NO_AUTH</term> <description>the client does not have permission.</description></item>
		/// </list></exception>
		internal::zk_get_acl_future get_acl_async(const char *path)
		{
			validate_path(path);
			return internal::zk_get_acl_future(m_handle, path);
		}

		/// <summary>Sets the acl associated with a node.</summary>
		/// <param name="path">the name of the node. Expressed as a file name with slashes separating ancestors of the node.</param>
		/// <param name="acl">the ACL vector.</param>
		/// <exception cref="zk_error">with one of the following codes:<list>
		/// <item><term>NO_NODE</term> <description>the node does not exist.</description></item>
		/// <item><term>NO_AUTH</term> <description>the client does not have permission.</description></item>
		/// <item><term>INVALID_ACL</term> <description>invalid ACL specified.</description></item>
		/// </list></exception>
		internal::zk_set_acl_future set_acl_async(const char *path, const std::vector<ZkAcl> & acl, int version = -1)
		{
			validate_path(path);
			return internal::zk_set_acl_future(m_handle, path, acl, version);
		}

		/// <summary>Atomically commits multiple zookeeper operations.</summary>
		/// <param name="tx">transaction which contains multiple operations to perform.</param>
		/// <returns>std::vector&lt;zk_op_result&gt; which contains separate result for each operation.</returns>
		internal::zk_multi_future multi_async(const zk_transaction & tx)
		{
			return internal::zk_multi_future(m_handle, tx);
		}

		/// <summary>Specify application credentials.</summary>
		/// <remarks>
		/// The application calls this function to specify its credentials for purposes
		/// of authentication.The server will use the security provider specified by
		/// the scheme parameter to authenticate the client connection.If the
		/// authentication request has failed :
		/// -the server connection is dropped
		/// -the watcher is called with the ZOO_AUTH_FAILED_STATE value as the state parameter.
		/// </remarks>
		/// <param name="scheme">the id of authentication scheme. Natively supported: "digest" password - based authentication</param>
		/// <param name="cert">application credentials. The actual value depends on the scheme.</param>
		/// <param name="certSize">the size of the cert parameter.</param>
		/// <exception cref="zk_error">with one of the following codes:<list>
		/// <item><term>NO_AUTH</term> <description>the client does not have permission.</description></item>
		/// </list></exception>
		internal::zk_add_auth_future add_auth_async(const char * scheme, const void * cert, size_t certSize)
		{
			return internal::zk_add_auth_future(m_handle, scheme, std::string((const char *)cert, (int)certSize));
		}

		/// <summary>Checks if the current zookeeper connection state can't be recovered.</summary>
		/// <remarks>The application must close the connection and try to reconnect.</remarks>
		bool is_unrecoverable()
		{
			int rc = internal::is_unrecoverable(m_handle);
			if (rc == INVALID_STATE)
				return true;
			zk_error::check(rc);
			return false;
		}
	};

}

#endif // !ASYNC_ZOOKEEPER_H_INCLUDED
