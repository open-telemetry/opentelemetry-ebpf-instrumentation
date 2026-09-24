require "active_support/core_ext/integer/time"

Rails.application.configure do
  # Reload application code between requests while developing.
  config.enable_reloading = true
  config.eager_load = false

  config.consider_all_requests_local = true
  config.server_timing = true

  config.action_controller.perform_caching = false
  config.cache_store = :null_store

  config.active_record.migration_error = :page_load
  config.active_record.verbose_query_logs = true
  config.active_record.query_log_tags_enabled = true

  config.active_support.deprecation = :log
end
