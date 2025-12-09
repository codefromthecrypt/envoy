#include "source/extensions/access_loggers/open_telemetry/grpc_access_log_impl.h"

#include "envoy/extensions/access_loggers/grpc/v3/als.pb.h"
#include "envoy/extensions/access_loggers/open_telemetry/v3/logs_service.pb.h"
#include "envoy/grpc/async_client_manager.h"
#include "envoy/local_info/local_info.h"

#include "source/common/config/utility.h"
#include "source/common/grpc/typed_async_client.h"
#include "source/common/protobuf/utility.h"
#include "source/extensions/access_loggers/common/grpc_access_logger_clients.h"
#include "source/extensions/access_loggers/open_telemetry/otlp_log_utils.h"

#include "opentelemetry/proto/collector/logs/v1/logs_service.pb.h"
#include "opentelemetry/proto/common/v1/common.pb.h"
#include "opentelemetry/proto/logs/v1/logs.pb.h"
#include "opentelemetry/proto/resource/v1/resource.pb.h"

const char GRPC_LOG_STATS_PREFIX[] = "access_logs.open_telemetry_access_log.";

namespace Envoy {
namespace Extensions {
namespace AccessLoggers {
namespace OpenTelemetry {

namespace {
using opentelemetry::proto::collector::logs::v1::ExportLogsServiceRequest;
using opentelemetry::proto::collector::logs::v1::ExportLogsServiceResponse;
} // namespace

GrpcAccessLoggerImpl::GrpcAccessLoggerImpl(
    const Grpc::RawAsyncClientSharedPtr& client,
    const envoy::extensions::access_loggers::open_telemetry::v3::OpenTelemetryAccessLogConfig&
        config,
    Event::Dispatcher& dispatcher, const LocalInfo::LocalInfo& local_info, Stats::Scope& scope,
    Tracers::OpenTelemetry::ResourceConstSharedPtr detected_resource)
    : GrpcAccessLogger(
          config.common_config(), dispatcher, scope, std::nullopt,
          std::make_unique<Common::UnaryGrpcAccessLogClient<ExportLogsServiceRequest,
                                                            ExportLogsServiceResponse>>(
              client,
              *Protobuf::DescriptorPool::generated_pool()->FindMethodByName(
                  "opentelemetry.proto.collector.logs.v1.LogsService.Export"),
              GrpcCommon::optionalRetryPolicy(config.common_config()), genOTelCallbacksFactory())),
      stats_({ALL_GRPC_ACCESS_LOGGER_STATS(
          POOL_COUNTER_PREFIX(scope, absl::StrCat(GRPC_LOG_STATS_PREFIX, config.stat_prefix())))}) {
  initMessageRoot(config, local_info, detected_resource);
}

std::function<GrpcAccessLoggerImpl::OTelLogRequestCallbacks&()>
GrpcAccessLoggerImpl::genOTelCallbacksFactory() {
  return [this]() -> OTelLogRequestCallbacks& {
    auto callback = std::make_unique<OTelLogRequestCallbacks>(
        this->stats_, this->batched_log_entries_, [this](OTelLogRequestCallbacks* p) {
          if (this->callbacks_.contains(p)) {
            this->callbacks_.erase(p);
          }
        });
    OTelLogRequestCallbacks* ptr = callback.get();
    this->batched_log_entries_ = 0;
    this->callbacks_.emplace(ptr, std::move(callback));
    return *ptr;
  };
}
// See comment about the structure of repeated fields in the header file.
void GrpcAccessLoggerImpl::initMessageRoot(
    const envoy::extensions::access_loggers::open_telemetry::v3::OpenTelemetryAccessLogConfig&
        config,
    const LocalInfo::LocalInfo& local_info,
    Tracers::OpenTelemetry::ResourceConstSharedPtr detected_resource) {
  auto* resource_logs = message_.add_resource_logs();
  root_ = resource_logs->add_scope_logs();
  auto* resource = resource_logs->mutable_resource();
  if (!config.disable_builtin_labels()) {
    *resource->add_attributes() = getStringKeyValue("log_name", getLogName(config));
    *resource->add_attributes() = getStringKeyValue("zone_name", local_info.zoneName());
    *resource->add_attributes() = getStringKeyValue("cluster_name", local_info.clusterName());
    *resource->add_attributes() = getStringKeyValue("node_name", local_info.nodeName());
  }

  // Add static resource_attributes from config (for backward compatibility).
  for (const auto& pair : config.resource_attributes().values()) {
    *resource->add_attributes() = pair;
  }

  // Add detected resource attributes (from resource_detectors).
  // These take precedence over static resource_attributes.
  if (detected_resource) {
    for (const auto& [key, value] : detected_resource->attributes_) {
      *resource->add_attributes() = getStringKeyValue(key, value);
    }
  }
}

void GrpcAccessLoggerImpl::addEntry(opentelemetry::proto::logs::v1::LogRecord&& entry) {
  batched_log_entries_++;
  root_->mutable_log_records()->Add(std::move(entry));
}

bool GrpcAccessLoggerImpl::isEmpty() { return root_->log_records().empty(); }

// The message is already initialized in the c'tor, and only the logs are cleared.
void GrpcAccessLoggerImpl::initMessage() {}

void GrpcAccessLoggerImpl::clearMessage() { root_->clear_log_records(); }

// Thread-local storage for detected resource.
thread_local Tracers::OpenTelemetry::ResourceConstSharedPtr
    GrpcAccessLoggerCacheImpl::tls_detected_resource_;

GrpcAccessLoggerCacheImpl::GrpcAccessLoggerCacheImpl(Grpc::AsyncClientManager& async_client_manager,
                                                     Stats::Scope& scope,
                                                     ThreadLocal::SlotAllocator& tls,
                                                     const LocalInfo::LocalInfo& local_info)
    : GrpcAccessLoggerCache(async_client_manager, scope, tls), local_info_(local_info) {}

void GrpcAccessLoggerCacheImpl::setDetectedResource(
    Tracers::OpenTelemetry::ResourceConstSharedPtr detected_resource) {
  tls_detected_resource_ = std::move(detected_resource);
}

GrpcAccessLoggerImpl::SharedPtr GrpcAccessLoggerCacheImpl::createLogger(
    const envoy::extensions::access_loggers::open_telemetry::v3::OpenTelemetryAccessLogConfig&
        config,
    Event::Dispatcher& dispatcher) {
  // We pass skip_cluster_check=true to factoryForGrpcService in order to avoid throwing
  // exceptions in worker threads. Call sites of this getOrCreateLogger must check the cluster
  // availability via ClusterManager::checkActiveStaticCluster beforehand, and throw exceptions in
  // the main thread if necessary to ensure it does not throw here.
  auto factory_or_error =
      async_client_manager_.factoryForGrpcService(getGrpcService(config), scope_, true);
  THROW_IF_NOT_OK_REF(factory_or_error.status());
  auto client = THROW_OR_RETURN_VALUE(factory_or_error.value()->createUncachedRawAsyncClient(),
                                      Grpc::RawAsyncClientPtr);
  // Use thread-local detected_resource and clear it after use.
  auto detected_resource = std::move(tls_detected_resource_);
  tls_detected_resource_.reset();
  return std::make_shared<GrpcAccessLoggerImpl>(std::move(client), config, dispatcher, local_info_,
                                                scope_, detected_resource);
}

} // namespace OpenTelemetry
} // namespace AccessLoggers
} // namespace Extensions
} // namespace Envoy
