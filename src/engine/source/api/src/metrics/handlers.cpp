#include "api/metrics/handlers.hpp"

#include <json/json.hpp>
#include <eMessages/eMessage.h>
#include <eMessages/metrics.pb.h>

#include <api/adapter.hpp>

namespace api::metrics::handlers
{

namespace eMetrics = ::com::wazuh::api::engine::metrics;
namespace eEngine = ::com::wazuh::api::engine;

/* Manager Endpoint */

api::Handler metricsDumpCmd(const std::shared_ptr<metricsManager::IMetricsManagerAPI>& metricsAPI)
{
    return [metricsAPI](api::wpRequest wRequest) -> api::wpResponse
    {
        using RequestType = eMetrics::Dump_Request;
        using ResponseType = eMetrics::Dump_Response;
        auto res = ::api::adapter::fromWazuhRequest<RequestType, ResponseType>(wRequest);

        // If the request is not valid, return the error
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }

        // Validate the params request
        const auto& eRequest = std::get<RequestType>(res);
        auto result = metricsAPI->dumpCmd();

        if (std::holds_alternative<base::Error>(result))
        {
            return ::api::adapter::genericError<ResponseType>(std::get<base::Error>(result).message);
        }

        const auto protoVal = eMessage::eMessageFromJson<google::protobuf::Value>(std::get<std::string>(result));
        const auto json_value = std::get<google::protobuf::Value>(protoVal);

        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);
        eResponse.mutable_value()->CopyFrom(json_value);

        return ::api::adapter::toWazuhResponse(eResponse);
    };
}


api::Handler metricsGetCmd(const std::shared_ptr<metricsManager::IMetricsManagerAPI>& metricsAPI)
{
    return [metricsAPI](api::wpRequest wRequest) -> api::wpResponse
    {
        using RequestType = eMetrics::Get_Request;
        using ResponseType = eMetrics::Get_Response;
        auto res = ::api::adapter::fromWazuhRequest<RequestType, ResponseType>(wRequest);

        // If the request is not valid, return the error
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }

        // Validate the params request
        const auto& eRequest = std::get<RequestType>(res);
        auto errorMsg = !eRequest.has_scopename()        ? std::make_optional("Missing /scope name")
                        : !eRequest.has_instrumentname() ? std::make_optional("Missing /instrument name")
                                                         : std::nullopt;

        if (errorMsg.has_value())
        {
            return ::api::adapter::genericError<ResponseType>(errorMsg.value());
        }

        auto result = metricsAPI->getCmd(eRequest.scopename(), eRequest.instrumentname());
        if (std::holds_alternative<base::Error>(result))
        {
            return ::api::adapter::genericError<ResponseType>(std::get<base::Error>(result).message);
        }

        const auto protoVal = eMessage::eMessageFromJson<google::protobuf::Value>(std::get<std::string>(result));
        const auto json_value = std::get<google::protobuf::Value>(protoVal);

        ResponseType eResponse;
        eResponse.mutable_value()->CopyFrom(json_value);
        eResponse.set_status(eEngine::ReturnStatus::OK);

        return ::api::adapter::toWazuhResponse(eResponse);
    };
}

api::Handler metricsEnableCmd(const std::shared_ptr<metricsManager::IMetricsManagerAPI>& metricsAPI)
{
    return [metricsAPI](api::wpRequest wRequest) -> api::wpResponse
    {
        using RequestType = eMetrics::Enable_Request;
        using ResponseType = eMetrics::Enable_Response;
        auto res = ::api::adapter::fromWazuhRequest<RequestType, ResponseType>(wRequest);

        // If the request is not valid, return the error
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }

        // Validate the params request
        const auto& eRequest = std::get<RequestType>(res);
        auto errorMsg = !eRequest.has_scopename()        ? std::make_optional("Missing /scope name")
                        : !eRequest.has_instrumentname() ? std::make_optional("Missing /instrument name")
                        : !eRequest.has_status()         ? std::make_optional("Missing /status")
                                                         : std::nullopt;

        if (errorMsg.has_value())
        {
            return ::api::adapter::genericError<ResponseType>(errorMsg.value());
        }

        try
        {
            metricsAPI->enableCmd(eRequest.scopename(), eRequest.instrumentname(), eRequest.status());
        }
        catch (const std::exception& e)
        {
            return ::api::adapter::genericError<ResponseType>(e.what());
        }

        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);

        return ::api::adapter::toWazuhResponse(eResponse);
    };
}

api::Handler metricsTestCmd(const std::shared_ptr<metricsManager::IMetricsManagerAPI>& metricsAPI)
{
    return [metricsAPI](api::wpRequest wRequest) -> api::wpResponse
    {
        using RequestType = eMetrics::Test_Request;
        using ResponseType = eMetrics::Test_Response;
        auto res = ::api::adapter::fromWazuhRequest<RequestType, ResponseType>(wRequest);

        // If the request is not valid, return the error
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }

        metricsAPI->testCmd();

        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);

        return ::api::adapter::toWazuhResponse(eResponse);
    };
}

api::Handler metricsList(const std::shared_ptr<metricsManager::IMetricsManagerAPI>& metricsAPI)
{
    std::variant<std::string, base::Error> result;
    return [metricsAPI](api::wpRequest wRequest) -> api::wpResponse
    {
        using RequestType = eMetrics::List_Request;
        using ResponseType = eMetrics::List_Response;
        auto res = ::api::adapter::fromWazuhRequest<RequestType, ResponseType>(wRequest);

        // If the request is not valid, return the error
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }

        // Validate the params request
        const auto& eRequest = std::get<RequestType>(res);
        auto result = metricsAPI->listCmd();
        ResponseType eResponse;

        if (std::holds_alternative<base::Error>(result))
        {
            return ::api::adapter::genericError<ResponseType>(std::get<base::Error>(result).message);
        }

        eResponse.set_status(eEngine::ReturnStatus::OK);

        const auto aux = std::get<std::string>(result);
        const auto protoVal = eMessage::eMessageFromJson<google::protobuf::Value>(aux);
        const auto json_value = std::get<google::protobuf::Value>(protoVal);
        eResponse.mutable_value()->CopyFrom(json_value);

        return ::api::adapter::toWazuhResponse(eResponse);
    };
}

void registerHandlers(const std::shared_ptr<metricsManager::IMetricsManagerAPI>& metricsAPI, std::shared_ptr<api::Registry> registry)
{
    try
    {
        registry->registerHandler("metrics.manager/dump", metricsDumpCmd(metricsAPI));
        registry->registerHandler("metrics.manager/get", metricsGetCmd(metricsAPI));
        registry->registerHandler("metrics.manager/enable", metricsEnableCmd(metricsAPI));
        registry->registerHandler("metrics.manager/test", metricsTestCmd(metricsAPI));
        registry->registerHandler("metrics.manager/list", metricsList(metricsAPI));
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error(fmt::format("metrics API commands could not be registered: {}", e.what()));
    }
}
} // namespace api::metrics::handlers