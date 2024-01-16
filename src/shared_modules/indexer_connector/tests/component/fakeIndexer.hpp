/*
 * Wazuh Indexer Connector - Component tests
 * Copyright (C) 2015, Wazuh Inc.
 * January 09, 2024.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _FAKE_OPEN_SEARCH_SERVER_HPP
#define _FAKE_OPEN_SEARCH_SERVER_HPP

#include <external/cpp-httplib/httplib.h>
#include <external/nlohmann/json.hpp>
#include <functional>
#include <sstream>
#include <string>
#include <thread>
#include <utility>

/**
 * @brief This class is a simple HTTP server that provides a fake OpenSearch server.
 */
class FakeIndexer
{
private:
    httplib::Server m_server;
    std::thread m_thread;
    int m_port;
    std::string m_host, m_health, m_indexName;
    bool m_indexerInitialized;
    std::function<void(const std::string&)> m_initTemplateCallback, m_initIndexCallback, m_publishCallback;

public:
    /**
     * @brief Class constructor.
     *
     * @param host Host of the server.
     * @param port Port of the server.
     * @param health Health status of the server.
     * @param indexName Name of the index.
     */
    FakeIndexer(std::string host, int port, std::string health, std::string indexName)
        : m_thread(&FakeIndexer::run, this)
        , m_host(std::move(host))
        , m_health(std::move(health))
        , m_port(port)
        , m_indexName(std::move(indexName))
        , m_indexerInitialized(false)
        , m_publishCallback({})
        , m_initIndexCallback({})
        , m_initTemplateCallback({})
    {
        // Wait until server is ready.
        while (!m_server.is_running())
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }

    ~FakeIndexer()
    {
        m_server.stop();
        if (m_thread.joinable())
        {
            m_thread.join();
        }
    }

    /**
     * @brief Sets the health of the server.
     *
     * @param health New health value.
     */
    void setHealth(std::string health)
    {
        m_health = health;
    }

    /**
     * @brief Sets the publish callback.
     *
     * @param callback New callback.
     */
    void setPublishCallback(std::function<void(const std::string&)> callback)
    {
        m_publishCallback = callback;
    }

    /**
     * @brief Sets the init index callback.
     *
     * @param callback New callback.
     */
    void setInitIndexCallback(std::function<void(const std::string&)> callback)
    {
        m_initIndexCallback = callback;
    }

    /**
     * @brief Sets the init template callback.
     *
     * @param callback New callback.
     */
    void setInitTemplateCallback(std::function<void(const std::string&)> callback)
    {
        m_initTemplateCallback = callback;
    }

    /**
     * @brief Returns a the initialized variable.
     *
     * @return True if initialized, false otherwise.
     */
    bool initialized() const
    {
        return m_indexerInitialized;
    }

    /**
     * @brief Starts the server and listens for new connections.
     *
     * Setups a fake OpenSearch endpoint, configures the server and starts listening
     * for new connections.
     *
     */
    void run()
    {
        // Endpoint where the health status is returned.
        m_server.Get(
            "/_cat/health",
            [this](const httplib::Request& req, httplib::Response& res)
            {
                std::stringstream ss;
                ss << "epoch      timestamp cluster            status node.total node.data discovered_cluster_manager "
                      "shards pri relo init unassign pending_tasks max_task_wait_time active_shards_percent\n";
                ss << "1694645550 22:52:30 opensearch-cluster " << m_health << " 2 2 true 14 7 0 0 0 0 - 100.0%\n";
                res.set_content(ss.str(), "text/plain");
            });

        // Endpoint where the index is initialized.
        m_server.Put("/" + m_indexName,
                     [this](const httplib::Request& req, httplib::Response& res)
                     {
                         try
                         {
                             if (m_initIndexCallback)
                             {
                                 m_initIndexCallback(req.body);
                             }
                             m_indexerInitialized = true;
                             res.status = 200;
                             res.set_content("Index initialized", "text/plain");
                         }
                         catch (const std::exception& e)
                         {
                             res.status = 500;
                             res.set_content(e.what(), "text/plain");
                         }
                     });

        // Endpoint where the template is initialized.
        m_server.Put("/_index_template/" + m_indexName + "_template",
                     [this](const httplib::Request& req, httplib::Response& res)
                     {
                         try
                         {
                             if (m_initTemplateCallback)
                             {
                                 m_initTemplateCallback(req.body);
                             }
                             res.status = 200;
                             res.set_content("Template initialized", "text/plain");
                         }
                         catch (const std::exception& e)
                         {
                             res.status = 500;
                             res.set_content(e.what(), "text/plain");
                         }
                     });

        // Endpoint where the publications are made into.
        m_server.Post("/_bulk",
                      [this](const httplib::Request& req, httplib::Response& res)
                      {
                          try
                          {
                              if (m_publishCallback)
                              {
                                  m_publishCallback(req.body);
                              }
                              res.status = 200;
                              res.set_content("Content published", "text/plain");
                          }
                          catch (const std::exception& e)
                          {
                              res.status = 500;
                              res.set_content(e.what(), "text/plain");
                          }
                      });

        m_server.set_keep_alive_max_count(1);
        m_server.listen(m_host.c_str(), m_port);
    }
};

#endif // _FAKE_OPEN_SEARCH_SERVER_HPP
