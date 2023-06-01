#ifndef _IKVDBHANDLERMANAGER_H
#define _IKVDBHANDLERMANAGER_H

#include <kvdb/iKVDBHandler.hpp>
#include <memory>
#include <string>

namespace kvdbManager
{

class IKVDBHandlerManager
{
public:
    virtual std::variant<std::unique_ptr<IKVDBHandler>, base::Error> getKVDBHandler(const std::string& dbName, const std::string& scopeName) = 0;
    virtual void removeKVDBHandler(const std::string& dbName, const std::string& scopeName) = 0;
    virtual bool skipAutoRemoveEnabled() = 0;
};

} // namespace kvdbManager

#endif // _IKVDBHANDLERMANAGER_H