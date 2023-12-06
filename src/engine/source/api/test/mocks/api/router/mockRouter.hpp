#ifndef _API_ROUTER_MOCK_ROUTER_HPP
#define _API_ROUTER_MOCK_ROUTER_HPP

#include <gmock/gmock.h>

#include <router/iapi.hpp>

namespace api::router::mocks
{

class MockRouterAPI : public ::router::IRouterAPI
{
public:
    MOCK_METHOD(base::OptError, postEntry, (const ::router::prod::EntryPost& entry), (override));
    MOCK_METHOD(base::OptError, deleteEntry, (const std::string& name), (override));
    MOCK_METHOD(base::RespOrError<::router::prod::Entry>, getEntry, (const std::string& name), (const, override));
    MOCK_METHOD(base::OptError, reloadEntry, (const std::string& name), (override));
    MOCK_METHOD(base::OptError, changeEntryPriority, (const std::string& name, size_t priority), (override));
    MOCK_METHOD(std::list<::router::prod::Entry>, getEntries, (), (const, override));
    MOCK_METHOD(void, postEvent, (base::Event&& event), (override));
    MOCK_METHOD(base::OptError, postStrEvent, (std::string_view event), (override));
};

}

#endif // _API_ROUTER_MOCK_ROUTER_HPP
