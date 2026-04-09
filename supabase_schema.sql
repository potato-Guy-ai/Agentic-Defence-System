-- Run this in Supabase SQL editor to create required tables

create table if not exists threat_logs (
  id bigserial primary key,
  ip text,
  threat text,
  action text,
  risk_score int,
  reason text,
  playbook text,
  created_at timestamptz default now()
);

create table if not exists blacklist (
  id bigserial primary key,
  ip text unique,
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
  status text default 'pending',  -- pending | approved | rejected
  created_at timestamptz default now()
);
