#pragma once

#include <string>

#include "envoy/extensions/access_loggers/open_telemetry/v3/logs_service.pb.h"

#include "source/common/common/hex.h"

#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "opentelemetry/proto/common/v1/common.pb.h"
#include "opentelemetry/proto/logs/v1/logs.pb.h"

namespace Envoy {
namespace Extensions {
namespace AccessLoggers {
namespace OpenTelemetry {

// Key used to pack/unpack the body AnyValue to a KeyValueList.
constexpr absl::string_view BodyKey = "body";

// OpenTelemetry trace ID length in hex (128-bit = 32 hex chars).
constexpr size_t TraceIdHexLength = 32;
// Zipkin-style trace ID length in hex (64-bit = 16 hex chars).
constexpr size_t ShortTraceIdHexLength = 16;

// Creates a KeyValue protobuf with a string value.
opentelemetry::proto::common::v1::KeyValue getStringKeyValue(const std::string& key,
                                                             const std::string& value);

// Packs the body "AnyValue" to a "KeyValueList" with a single key.
::opentelemetry::proto::common::v1::KeyValueList
packBody(const ::opentelemetry::proto::common::v1::AnyValue& body);

// Unpacks the body "AnyValue" from a "KeyValueList".
::opentelemetry::proto::common::v1::AnyValue
unpackBody(const ::opentelemetry::proto::common::v1::KeyValueList& value);

// User-Agent header per OTLP specification.
const std::string& getOtlpUserAgentHeader();

// Populates trace context (trace_id, span_id) on a LogRecord.
// Handles 128-bit (32 hex chars) and 64-bit Zipkin-style (16 hex chars) trace IDs.
void populateTraceContext(opentelemetry::proto::logs::v1::LogRecord& log_entry,
                          const std::string& trace_id_hex, const std::string& span_id_hex);

// Helper functions for config field resolution with fallback to common_config.
// Returns top-level log_name, or falls back to common_config.log_name.
const std::string& getLogName(
    const envoy::extensions::access_loggers::open_telemetry::v3::OpenTelemetryAccessLogConfig&
        config);

// Returns top-level grpc_service, or falls back to common_config.grpc_service.
const envoy::config::core::v3::GrpcService& getGrpcService(
    const envoy::extensions::access_loggers::open_telemetry::v3::OpenTelemetryAccessLogConfig&
        config);

} // namespace OpenTelemetry
} // namespace AccessLoggers
} // namespace Extensions
} // namespace Envoy
