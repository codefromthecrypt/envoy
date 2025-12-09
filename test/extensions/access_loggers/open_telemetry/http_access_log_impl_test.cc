#include "source/extensions/access_loggers/open_telemetry/http_access_log_impl.h"

#include "test/mocks/event/mocks.h"
#include "test/mocks/local_info/mocks.h"
#include "test/mocks/stats/mocks.h"
#include "test/mocks/tracing/mocks.h"
#include "test/mocks/upstream/cluster_manager.h"
#include "test/test_common/utility.h"

#include "absl/strings/match.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "opentelemetry/proto/collector/logs/v1/logs_service.pb.h"

namespace Envoy {
namespace Extensions {
namespace AccessLoggers {
namespace OpenTelemetry {

using testing::_;
using testing::Invoke;
using testing::Return;
using testing::ReturnRef;

const std::string ZONE_NAME = "test_zone";
const std::string CLUSTER_NAME = "test_cluster";
const std::string NODE_NAME = "test_node";

class HttpAccessLoggerImplTest : public testing::Test {
public:
  HttpAccessLoggerImplTest() : timer_(new Event::MockTimer(&dispatcher_)) {
    EXPECT_CALL(*timer_, enableTimer(_, _)).Times(testing::AnyNumber());
  }

  void setup(envoy::config::core::v3::HttpService http_service) {
    envoy::extensions::access_loggers::open_telemetry::v3::OpenTelemetryAccessLogConfig config;
    setupWithConfig(http_service, config);
  }

  void setupWithConfig(
      envoy::config::core::v3::HttpService http_service,
      envoy::extensions::access_loggers::open_telemetry::v3::OpenTelemetryAccessLogConfig config) {
    cluster_manager_.thread_local_cluster_.cluster_.info_->name_ = "my_o11y_backend";
    cluster_manager_.initializeThreadLocalClusters({"my_o11y_backend"});
    ON_CALL(cluster_manager_.thread_local_cluster_, httpAsyncClient())
        .WillByDefault(ReturnRef(cluster_manager_.thread_local_cluster_.async_client_));

    cluster_manager_.initializeClusters({"my_o11y_backend"}, {});

    ON_CALL(local_info_, zoneName()).WillByDefault(ReturnRef(ZONE_NAME));
    ON_CALL(local_info_, clusterName()).WillByDefault(ReturnRef(CLUSTER_NAME));
    ON_CALL(local_info_, nodeName()).WillByDefault(ReturnRef(NODE_NAME));

    http_access_logger_ =
        std::make_unique<HttpAccessLoggerImpl>(cluster_manager_, http_service, config, dispatcher_,
                                               local_info_, *stats_store_.rootScope(), nullptr);
  }

protected:
  NiceMock<Upstream::MockClusterManager> cluster_manager_;
  NiceMock<Event::MockDispatcher> dispatcher_;
  Event::MockTimer* timer_;
  NiceMock<LocalInfo::MockLocalInfo> local_info_;
  NiceMock<Stats::MockIsolatedStatsStore> stats_store_;
  std::unique_ptr<HttpAccessLoggerImpl> http_access_logger_;
};

// Verifies OTLP HTTP export with custom headers, proper method, content-type, and user-agent.
TEST_F(HttpAccessLoggerImplTest, CreateExporterAndExportLog) {
  std::string yaml_string = R"EOF(
  http_uri:
    uri: "https://some-o11y.com/otlp/v1/logs"
    cluster: "my_o11y_backend"
    timeout: 0.250s
  request_headers_to_add:
  - header:
      key: "Authorization"
      value: "auth-token"
  - header:
      key: "x-custom-header"
      value: "custom-value"
  )EOF";

  envoy::config::core::v3::HttpService http_service;
  TestUtility::loadFromYaml(yaml_string, http_service);
  setup(http_service);

  Http::MockAsyncClientRequest request(&cluster_manager_.thread_local_cluster_.async_client_);
  Http::AsyncClient::Callbacks* callback;

  EXPECT_CALL(cluster_manager_.thread_local_cluster_.async_client_,
              send_(_, _,
                    Http::AsyncClient::RequestOptions()
                        .setTimeout(std::chrono::milliseconds(250))
                        .setDiscardResponseBody(true)))
      .WillOnce(
          Invoke([&](Http::RequestMessagePtr& message, Http::AsyncClient::Callbacks& callbacks,
                     const Http::AsyncClient::RequestOptions&) -> Http::AsyncClient::Request* {
            callback = &callbacks;

            // Verify OTLP HTTP spec compliance: POST method and protobuf content-type.
            EXPECT_EQ(Http::Headers::get().MethodValues.Post, message->headers().getMethodValue());
            EXPECT_EQ(Http::Headers::get().ContentTypeValues.Protobuf,
                      message->headers().getContentTypeValue());

            EXPECT_EQ("/otlp/v1/logs", message->headers().getPathValue());
            EXPECT_EQ("some-o11y.com", message->headers().getHostValue());

            // Verify User-Agent follows OTLP spec.
            EXPECT_TRUE(absl::StartsWith(message->headers().getUserAgentValue(),
                                         "OTel-OTLP-Exporter-Envoy/"));

            // Custom headers provided in the configuration.
            EXPECT_EQ("auth-token", message->headers()
                                        .get(Http::LowerCaseString("authorization"))[0]
                                        ->value()
                                        .getStringView());
            EXPECT_EQ("custom-value", message->headers()
                                          .get(Http::LowerCaseString("x-custom-header"))[0]
                                          ->value()
                                          .getStringView());

            return &request;
          }));

  opentelemetry::proto::logs::v1::LogRecord log_record;
  log_record.set_severity_number(opentelemetry::proto::logs::v1::SEVERITY_NUMBER_INFO);
  log_record.mutable_body()->set_string_value("test log message");
  http_access_logger_->log(std::move(log_record));

  // Trigger flush via timer callback.
  timer_->invokeCallback();

  Http::ResponseMessagePtr msg(new Http::ResponseMessageImpl(
      Http::ResponseHeaderMapPtr{new Http::TestResponseHeaderMapImpl{{":status", "200"}}}));

  // onBeforeFinalizeUpstreamSpan is a no-op, included for coverage.
  Tracing::NullSpan null_span;
  callback->onBeforeFinalizeUpstreamSpan(null_span, nullptr);

  callback->onSuccess(request, std::move(msg));
}

// Verifies that export is aborted gracefully when the cluster is not found.
TEST_F(HttpAccessLoggerImplTest, UnsuccessfulLogWithoutThreadLocalCluster) {
  std::string yaml_string = R"EOF(
  http_uri:
    uri: "https://some-o11y.com/otlp/v1/logs"
    cluster: "my_o11y_backend"
    timeout: 10s
  )EOF";

  envoy::config::core::v3::HttpService http_service;
  TestUtility::loadFromYaml(yaml_string, http_service);
  setup(http_service);

  ON_CALL(cluster_manager_, getThreadLocalCluster(absl::string_view("my_o11y_backend")))
      .WillByDefault(Return(nullptr));

  opentelemetry::proto::logs::v1::LogRecord log_record;
  log_record.set_severity_number(opentelemetry::proto::logs::v1::SEVERITY_NUMBER_INFO);
  log_record.mutable_body()->set_string_value("test log message");
  http_access_logger_->log(std::move(log_record));

  // Trigger flush via timer callback - the log should be dropped since cluster is not available.
  timer_->invokeCallback();
}

// Verifies that non-success HTTP status codes (e.g., 503) are handled gracefully.
TEST_F(HttpAccessLoggerImplTest, ExportLogsNonSuccessStatusCode) {
  std::string yaml_string = R"EOF(
  http_uri:
    uri: "https://some-o11y.com/otlp/v1/logs"
    cluster: "my_o11y_backend"
    timeout: 0.250s
  )EOF";

  envoy::config::core::v3::HttpService http_service;
  TestUtility::loadFromYaml(yaml_string, http_service);
  setup(http_service);

  Http::MockAsyncClientRequest request(&cluster_manager_.thread_local_cluster_.async_client_);
  Http::AsyncClient::Callbacks* callback;

  EXPECT_CALL(cluster_manager_.thread_local_cluster_.async_client_, send_(_, _, _))
      .WillOnce(
          Invoke([&](Http::RequestMessagePtr&, Http::AsyncClient::Callbacks& callbacks,
                     const Http::AsyncClient::RequestOptions&) -> Http::AsyncClient::Request* {
            callback = &callbacks;
            return &request;
          }));

  opentelemetry::proto::logs::v1::LogRecord log_record;
  log_record.set_severity_number(opentelemetry::proto::logs::v1::SEVERITY_NUMBER_ERROR);
  log_record.mutable_body()->set_string_value("error log message");
  http_access_logger_->log(std::move(log_record));

  // Trigger flush via timer callback.
  timer_->invokeCallback();

  // Simulate a 503 response.
  Http::ResponseMessagePtr msg(new Http::ResponseMessageImpl(
      Http::ResponseHeaderMapPtr{new Http::TestResponseHeaderMapImpl{{":status", "503"}}}));
  callback->onSuccess(request, std::move(msg));
}

// Verifies that HTTP request failures (e.g., connection reset) are handled gracefully.
TEST_F(HttpAccessLoggerImplTest, ExportLogsHttpFailure) {
  std::string yaml_string = R"EOF(
  http_uri:
    uri: "https://some-o11y.com/otlp/v1/logs"
    cluster: "my_o11y_backend"
    timeout: 0.250s
  )EOF";

  envoy::config::core::v3::HttpService http_service;
  TestUtility::loadFromYaml(yaml_string, http_service);
  setup(http_service);

  Http::MockAsyncClientRequest request(&cluster_manager_.thread_local_cluster_.async_client_);
  Http::AsyncClient::Callbacks* callback;

  EXPECT_CALL(cluster_manager_.thread_local_cluster_.async_client_, send_(_, _, _))
      .WillOnce(
          Invoke([&](Http::RequestMessagePtr&, Http::AsyncClient::Callbacks& callbacks,
                     const Http::AsyncClient::RequestOptions&) -> Http::AsyncClient::Request* {
            callback = &callbacks;
            return &request;
          }));

  opentelemetry::proto::logs::v1::LogRecord log_record;
  log_record.set_severity_number(opentelemetry::proto::logs::v1::SEVERITY_NUMBER_INFO);
  log_record.mutable_body()->set_string_value("test log message");
  http_access_logger_->log(std::move(log_record));

  // Trigger flush via timer callback.
  timer_->invokeCallback();

  callback->onFailure(request, Http::AsyncClient::FailureReason::Reset);
}

// Verifies that log_name is read from common_config and included in resource attributes.
TEST_F(HttpAccessLoggerImplTest, LogNameFromCommonConfig) {
  std::string yaml_string = R"EOF(
  http_uri:
    uri: "https://some-o11y.com/otlp/v1/logs"
    cluster: "my_o11y_backend"
    timeout: 0.250s
  )EOF";

  envoy::config::core::v3::HttpService http_service;
  TestUtility::loadFromYaml(yaml_string, http_service);

  envoy::extensions::access_loggers::open_telemetry::v3::OpenTelemetryAccessLogConfig config;
  config.mutable_common_config()->set_log_name("custom_log_name");
  setupWithConfig(http_service, config);

  Http::MockAsyncClientRequest request(&cluster_manager_.thread_local_cluster_.async_client_);
  Http::AsyncClient::Callbacks* callback;
  opentelemetry::proto::collector::logs::v1::ExportLogsServiceRequest captured_request;

  EXPECT_CALL(cluster_manager_.thread_local_cluster_.async_client_, send_(_, _, _))
      .WillOnce(
          Invoke([&](Http::RequestMessagePtr& message, Http::AsyncClient::Callbacks& callbacks,
                     const Http::AsyncClient::RequestOptions&) -> Http::AsyncClient::Request* {
            callback = &callbacks;
            // Parse the request body to verify resource attributes.
            captured_request.ParseFromString(message->body().toString());
            return &request;
          }));

  opentelemetry::proto::logs::v1::LogRecord log_record;
  log_record.set_severity_number(opentelemetry::proto::logs::v1::SEVERITY_NUMBER_INFO);
  http_access_logger_->log(std::move(log_record));

  timer_->invokeCallback();

  // Complete the request to avoid crash during teardown.
  Http::ResponseMessagePtr msg(new Http::ResponseMessageImpl(
      Http::ResponseHeaderMapPtr{new Http::TestResponseHeaderMapImpl{{":status", "200"}}}));
  callback->onSuccess(request, std::move(msg));

  // Verify log_name from common_config is used.
  ASSERT_EQ(1, captured_request.resource_logs_size());
  const auto& resource = captured_request.resource_logs(0).resource();
  ASSERT_GE(resource.attributes_size(), 4);
  EXPECT_EQ("log_name", resource.attributes(0).key());
  EXPECT_EQ("custom_log_name", resource.attributes(0).value().string_value());
  EXPECT_EQ("zone_name", resource.attributes(1).key());
  EXPECT_EQ(ZONE_NAME, resource.attributes(1).value().string_value());
  EXPECT_EQ("cluster_name", resource.attributes(2).key());
  EXPECT_EQ(CLUSTER_NAME, resource.attributes(2).value().string_value());
  EXPECT_EQ("node_name", resource.attributes(3).key());
  EXPECT_EQ(NODE_NAME, resource.attributes(3).value().string_value());
}

// Verifies that disable_builtin_labels=true excludes all builtin labels from resource attributes.
TEST_F(HttpAccessLoggerImplTest, DisableBuiltinLabels) {
  std::string yaml_string = R"EOF(
  http_uri:
    uri: "https://some-o11y.com/otlp/v1/logs"
    cluster: "my_o11y_backend"
    timeout: 0.250s
  )EOF";

  envoy::config::core::v3::HttpService http_service;
  TestUtility::loadFromYaml(yaml_string, http_service);

  envoy::extensions::access_loggers::open_telemetry::v3::OpenTelemetryAccessLogConfig config;
  config.mutable_common_config()->set_log_name("test_log");
  config.set_disable_builtin_labels(true);
  setupWithConfig(http_service, config);

  Http::MockAsyncClientRequest request(&cluster_manager_.thread_local_cluster_.async_client_);
  Http::AsyncClient::Callbacks* callback;
  opentelemetry::proto::collector::logs::v1::ExportLogsServiceRequest captured_request;

  EXPECT_CALL(cluster_manager_.thread_local_cluster_.async_client_, send_(_, _, _))
      .WillOnce(
          Invoke([&](Http::RequestMessagePtr& message, Http::AsyncClient::Callbacks& callbacks,
                     const Http::AsyncClient::RequestOptions&) -> Http::AsyncClient::Request* {
            callback = &callbacks;
            captured_request.ParseFromString(message->body().toString());
            return &request;
          }));

  opentelemetry::proto::logs::v1::LogRecord log_record;
  log_record.set_severity_number(opentelemetry::proto::logs::v1::SEVERITY_NUMBER_INFO);
  http_access_logger_->log(std::move(log_record));

  timer_->invokeCallback();

  // Complete the request to avoid crash during teardown.
  Http::ResponseMessagePtr msg(new Http::ResponseMessageImpl(
      Http::ResponseHeaderMapPtr{new Http::TestResponseHeaderMapImpl{{":status", "200"}}}));
  callback->onSuccess(request, std::move(msg));

  // Verify no builtin labels are present.
  ASSERT_EQ(1, captured_request.resource_logs_size());
  const auto& resource = captured_request.resource_logs(0).resource();
  EXPECT_EQ(0, resource.attributes_size());
}

// Verifies that resource_attributes are merged with builtin labels.
TEST_F(HttpAccessLoggerImplTest, ResourceAttributesMergedWithBuiltinLabels) {
  std::string yaml_string = R"EOF(
  http_uri:
    uri: "https://some-o11y.com/otlp/v1/logs"
    cluster: "my_o11y_backend"
    timeout: 0.250s
  )EOF";

  envoy::config::core::v3::HttpService http_service;
  TestUtility::loadFromYaml(yaml_string, http_service);

  envoy::extensions::access_loggers::open_telemetry::v3::OpenTelemetryAccessLogConfig config;
  config.mutable_common_config()->set_log_name("test_log");
  // Add custom resource attributes.
  auto* kv = config.mutable_resource_attributes()->add_values();
  kv->set_key("custom_key");
  kv->mutable_value()->set_string_value("custom_value");
  setupWithConfig(http_service, config);

  Http::MockAsyncClientRequest request(&cluster_manager_.thread_local_cluster_.async_client_);
  Http::AsyncClient::Callbacks* callback;
  opentelemetry::proto::collector::logs::v1::ExportLogsServiceRequest captured_request;

  EXPECT_CALL(cluster_manager_.thread_local_cluster_.async_client_, send_(_, _, _))
      .WillOnce(
          Invoke([&](Http::RequestMessagePtr& message, Http::AsyncClient::Callbacks& callbacks,
                     const Http::AsyncClient::RequestOptions&) -> Http::AsyncClient::Request* {
            callback = &callbacks;
            captured_request.ParseFromString(message->body().toString());
            return &request;
          }));

  opentelemetry::proto::logs::v1::LogRecord log_record;
  log_record.set_severity_number(opentelemetry::proto::logs::v1::SEVERITY_NUMBER_INFO);
  http_access_logger_->log(std::move(log_record));

  timer_->invokeCallback();

  // Complete the request to avoid crash during teardown.
  Http::ResponseMessagePtr msg(new Http::ResponseMessageImpl(
      Http::ResponseHeaderMapPtr{new Http::TestResponseHeaderMapImpl{{":status", "200"}}}));
  callback->onSuccess(request, std::move(msg));

  // Verify builtin labels + custom attributes are present.
  ASSERT_EQ(1, captured_request.resource_logs_size());
  const auto& resource = captured_request.resource_logs(0).resource();
  ASSERT_EQ(5, resource.attributes_size());
  // First 4 are builtin labels.
  EXPECT_EQ("log_name", resource.attributes(0).key());
  EXPECT_EQ("test_log", resource.attributes(0).value().string_value());
  // Last one is custom attribute.
  EXPECT_EQ("custom_key", resource.attributes(4).key());
  EXPECT_EQ("custom_value", resource.attributes(4).value().string_value());
}

} // namespace OpenTelemetry
} // namespace AccessLoggers
} // namespace Extensions
} // namespace Envoy
