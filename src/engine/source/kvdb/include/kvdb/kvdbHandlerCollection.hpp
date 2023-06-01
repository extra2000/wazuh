#ifndef _KVDBHANDLERCOLLECTION_H
#define _KVDBHANDLERCOLLECTION_H

#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>

#include <kvdb/kvdbSpace.hpp>
#include <kvdb/refCounter.hpp>

namespace kvdbManager
{

class KVDBScope;
class IKVDBHandlerManager;

class KVDBHandlerCollection
{
public:
    KVDBHandlerCollection(IKVDBHandlerManager* handleManager)
        : m_handleManager(handleManager)
    {
    }

    std::unique_ptr<IKVDBHandler> getKVDBHandler(rocksdb::DB* db,
                               rocksdb::ColumnFamilyHandle* cfHandle,
                               const std::string& dbName,
                               const std::string& scopeName);

    void removeKVDBHandler(const std::string& dbName, const std::string& scopeName, bool& isRemoved);

    std::vector<std::string> getDBNames();
    std::map<std::string, int> getRefMap(const std::string& dbName);

private:
    class KVDBHandlerInstance
    {
    public:
        void addScope(const std::string& scopeName);
        void removeScope(const std::string& scopeName);
        bool emptyScopes() const;
        std::vector<std::string> getRefNames() const;
        std::map<std::string, int> getRefMap() const;

    private:
        RefCounter m_scopeCounter;
    };

private:
    std::map<std::string, std::shared_ptr<KVDBHandlerInstance>> m_mapInstances;

    IKVDBHandlerManager* m_handleManager {nullptr};
    std::mutex m_mutex;
};

} // namespace kvdbManager

#endif // _KVDBHANDLERCOLLECTION_H