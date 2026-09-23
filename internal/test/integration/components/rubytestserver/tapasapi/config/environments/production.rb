Rails.application.configure do
  config.cache_classes = true
  config.eager_load = true
  config.consider_all_requests_local = false
  config.action_controller.perform_caching = true
  config.log_level = :info
  config.log_tags = [:request_id]
  config.active_support.report_deprecations = false
  config.active_record.dump_schema_after_migration = false
  config.hosts.clear
end
