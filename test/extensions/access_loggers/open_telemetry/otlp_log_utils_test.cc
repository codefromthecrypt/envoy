#include "source/extensions/access_loggers/open_telemetry/otlp_log_utils.h"

#include "test/test_common/utility.h"

#include "gtest/gtest.h"

namespace Envoy {
namespace Extensions {
namespace AccessLoggers {
namespace OpenTelemetry {
namespace {

TEST(OtlpLogUtilsTest, GetStringKeyValue) {
  auto kv = getStringKeyValue("test_key", "test_value");
  EXPECT_EQ("test_key", kv.key());
  EXPECT_EQ("test_value", kv.value().string_value());
}

TEST(OtlpLogUtilsTest, PackUnpackBody) {
  ::opentelemetry::proto::common::v1::AnyValue body;
  body.set_string_value("test body content");

  auto packed = packBody(body);
  ASSERT_EQ(1, packed.values().size());
  EXPECT_EQ(BodyKey, packed.values(0).key());

  auto unpacked = unpackBody(packed);
  EXPECT_EQ("test body content", unpacked.string_value());
}

TEST(OtlpLogUtilsTest, GetOtlpUserAgentHeader) {
  const auto& header = getOtlpUserAgentHeader();
  EXPECT_TRUE(absl::StartsWith(header, "OTel-OTLP-Exporter-Envoy/"));
  // Should return the same instance each time.
  EXPECT_EQ(&header, &getOtlpUserAgentHeader());
}

TEST(OtlpLogUtilsTest, PopulateTraceContextFullTraceId) {
  opentelemetry::proto::logs::v1::LogRecord log_entry;
  // 32-char (128-bit) trace ID.
  const std::string trace_id_hex = "0123456789abcdef0123456789abcdef";
  const std::string span_id_hex = "0123456789abcdef";

  populateTraceContext(log_entry, trace_id_hex, span_id_hex);

  EXPECT_EQ(16, log_entry.trace_id().size());
  EXPECT_EQ(8, log_entry.span_id().size());
  // Verify the hex conversion is correct.
  EXPECT_EQ(absl::HexStringToBytes(trace_id_hex), log_entry.trace_id());
  EXPECT_EQ(absl::HexStringToBytes(span_id_hex), log_entry.span_id());
}

TEST(OtlpLogUtilsTest, PopulateTraceContextShortTraceId) {
  opentelemetry::proto::logs::v1::LogRecord log_entry;
  // 16-char (64-bit, Zipkin-style) trace ID.
  const std::string short_trace_id_hex = "0123456789abcdef";
  const std::string span_id_hex = "fedcba9876543210";

  populateTraceContext(log_entry, short_trace_id_hex, span_id_hex);

  EXPECT_EQ(16, log_entry.trace_id().size());
  EXPECT_EQ(8, log_entry.span_id().size());
  // Should be padded with zeros on the left.
  const std::string expected_trace_id = "0000000000000000" + short_trace_id_hex;
  EXPECT_EQ(absl::HexStringToBytes(expected_trace_id), log_entry.trace_id());
}

TEST(OtlpLogUtilsTest, PopulateTraceContextEmptyIds) {
  opentelemetry::proto::logs::v1::LogRecord log_entry;

  populateTraceContext(log_entry, "", "");

  EXPECT_TRUE(log_entry.trace_id().empty());
  EXPECT_TRUE(log_entry.span_id().empty());
}

TEST(OtlpLogUtilsTest, PopulateTraceContextInvalidTraceIdLength) {
  opentelemetry::proto::logs::v1::LogRecord log_entry;
  // Invalid length (not 16 or 32 chars).
  const std::string invalid_trace_id = "0123456789";
  const std::string span_id_hex = "0123456789abcdef";

  populateTraceContext(log_entry, invalid_trace_id, span_id_hex);

  // Trace ID should not be set for invalid length.
  EXPECT_TRUE(log_entry.trace_id().empty());
  // Span ID should still be set.
  EXPECT_EQ(8, log_entry.span_id().size());
}

// Tests for config helper functions with fallback to deprecated common_config.

// Verifies that top-level log_name takes precedence over common_config.log_name.
TEST(OtlpLogUtilsTest, GetLogNamePrefersTopLevel) {
  envoy::extensions::access_loggers::open_telemetry::v3::OpenTelemetryAccessLogConfig config;
  config.set_log_name("top_level_log");
  config.mutable_common_config()->set_log_name("common_config_log");

  EXPECT_EQ("top_level_log", getLogName(config));
}

// Verifies fallback to common_config.log_name when top-level is not set.
TEST(OtlpLogUtilsTest, GetLogNameFallsBackToCommonConfig) {
  envoy::extensions::access_loggers::open_telemetry::v3::OpenTelemetryAccessLogConfig config;
  config.mutable_common_config()->set_log_name("common_config_log");

  EXPECT_EQ("common_config_log", getLogName(config));
}

// Verifies that an empty string is returned when neither is set.
TEST(OtlpLogUtilsTest, GetLogNameReturnsEmptyWhenNotSet) {
  envoy::extensions::access_loggers::open_telemetry::v3::OpenTelemetryAccessLogConfig config;

  EXPECT_TRUE(getLogName(config).empty());
}

// Verifies that top-level grpc_service takes precedence over common_config.grpc_service.
TEST(OtlpLogUtilsTest, GetGrpcServicePrefersTopLevel) {
  envoy::extensions::access_loggers::open_telemetry::v3::OpenTelemetryAccessLogConfig config;
  config.mutable_grpc_service()->mutable_envoy_grpc()->set_cluster_name("top_level_cluster");
  config.mutable_common_config()->mutable_grpc_service()->mutable_envoy_grpc()->set_cluster_name(
      "common_config_cluster");

  const auto& grpc_service = getGrpcService(config);
  EXPECT_EQ("top_level_cluster", grpc_service.envoy_grpc().cluster_name());
}

// Verifies fallback to common_config.grpc_service when top-level is not set.
TEST(OtlpLogUtilsTest, GetGrpcServiceFallsBackToCommonConfig) {
  envoy::extensions::access_loggers::open_telemetry::v3::OpenTelemetryAccessLogConfig config;
  config.mutable_common_config()->mutable_grpc_service()->mutable_envoy_grpc()->set_cluster_name(
      "common_config_cluster");

  const auto& grpc_service = getGrpcService(config);
  EXPECT_EQ("common_config_cluster", grpc_service.envoy_grpc().cluster_name());
}

} // namespace
} // namespace OpenTelemetry
} // namespace AccessLoggers
} // namespace Extensions
} // namespace Envoy
