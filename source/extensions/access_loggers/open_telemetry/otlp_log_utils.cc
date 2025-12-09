#include "source/extensions/access_loggers/open_telemetry/otlp_log_utils.h"

#include <string>

#include "source/common/common/assert.h"
#include "source/common/common/macros.h"
#include "source/common/version/version.h"

namespace Envoy {
namespace Extensions {
namespace AccessLoggers {
namespace OpenTelemetry {

opentelemetry::proto::common::v1::KeyValue getStringKeyValue(const std::string& key,
                                                             const std::string& value) {
  opentelemetry::proto::common::v1::KeyValue keyValue;
  keyValue.set_key(key);
  keyValue.mutable_value()->set_string_value(value);
  return keyValue;
}

::opentelemetry::proto::common::v1::KeyValueList
packBody(const ::opentelemetry::proto::common::v1::AnyValue& body) {
  ::opentelemetry::proto::common::v1::KeyValueList output;
  auto* kv = output.add_values();
  kv->set_key(std::string(BodyKey));
  *kv->mutable_value() = body;
  return output;
}

::opentelemetry::proto::common::v1::AnyValue
unpackBody(const ::opentelemetry::proto::common::v1::KeyValueList& value) {
  ASSERT(value.values().size() == 1 && value.values(0).key() == BodyKey);
  return value.values(0).value();
}

// User-Agent header follows the OTLP specification:
// https://github.com/open-telemetry/opentelemetry-specification/blob/v1.30.0/specification/protocol/exporter.md#user-agent
const std::string& getOtlpUserAgentHeader() {
  CONSTRUCT_ON_FIRST_USE(std::string, "OTel-OTLP-Exporter-Envoy/" + VersionInfo::version());
}

void populateTraceContext(opentelemetry::proto::logs::v1::LogRecord& log_entry,
                          const std::string& trace_id_hex, const std::string& span_id_hex) {
  // Sets trace_id if available. OpenTelemetry trace_id is a 16-byte array, and backends
  // (e.g. OTel-collector) will reject requests if the length is incorrect. Some trace
  // providers (e.g. Zipkin) return a 64-bit hex string, which must be padded to 128-bit.
  if (trace_id_hex.size() == TraceIdHexLength) {
    *log_entry.mutable_trace_id() = absl::HexStringToBytes(trace_id_hex);
  } else if (trace_id_hex.size() == ShortTraceIdHexLength) {
    const auto trace_id = absl::StrCat(Hex::uint64ToHex(0), trace_id_hex);
    *log_entry.mutable_trace_id() = absl::HexStringToBytes(trace_id);
  }
  // Sets span_id if available.
  if (!span_id_hex.empty()) {
    *log_entry.mutable_span_id() = absl::HexStringToBytes(span_id_hex);
  }
}

const std::string& getLogName(
    const envoy::extensions::access_loggers::open_telemetry::v3::OpenTelemetryAccessLogConfig&
        config) {
  // Prefer top-level log_name, fall back to common_config.log_name (deprecated).
  if (!config.log_name().empty()) {
    return config.log_name();
  }
  return config.common_config().log_name();
}

const envoy::config::core::v3::GrpcService& getGrpcService(
    const envoy::extensions::access_loggers::open_telemetry::v3::OpenTelemetryAccessLogConfig&
        config) {
  // Prefer top-level grpc_service, fall back to common_config.grpc_service (deprecated).
  if (config.has_grpc_service()) {
    return config.grpc_service();
  }
  return config.common_config().grpc_service();
}

} // namespace OpenTelemetry
} // namespace AccessLoggers
} // namespace Extensions
} // namespace Envoy
