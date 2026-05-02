-- Run once in Supabase SQL editor

create table if not exists threat_logs (
  id bigserial primary key,
  ip text,
  threat text,
  action text,
  risk_score int,
  unified_risk int,
  reason text,
  playbook text,
  geo jsonb,
  risk_breakdown jsonb,
  created_at timestamptz default now()
);

create table if not exists blacklist (
  id bigserial primary key,
  ip text unique not null,
  created_at timestamptz default now()
);

create table if not exists anomaly_candidates (
  id bigserial primary key,
  ip text,
  threat text,
  event_type text,
  confidence float,
  created_at timestamptz default now()
);

create table if not exists suggested_rules (
  id bigserial primary key,
  event_type text,
  suggested_threat text,
  occurrences int,
  suggested_confidence float,
  status text default 'pending',
  created_at timestamptz default now()
);

create table if not exists sessions (
  id bigserial primary key,
  session_id text,
  ip text,
  event_type text,
  threat text,
  created_at timestamptz default now()
);

create index if not exists idx_threat_logs_action on threat_logs(action);
create index if not exists idx_threat_logs_ip on threat_logs(ip);
create index if not exists idx_suggested_rules_status on suggested_rules(status);
create index if not exists idx_anomaly_candidates_event on anomaly_candidates(event_type);
create index if not exists idx_sessions_session_id on sessions(session_id);
