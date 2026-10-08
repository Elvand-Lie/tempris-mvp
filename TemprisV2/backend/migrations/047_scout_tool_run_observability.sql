ALTER TABLE scout_tool_runs ADD COLUMN sanitized_output_excerpt TEXT NULL;
ALTER TABLE scout_tool_runs ADD COLUMN parse_stats JSONB NULL;
