/*
 * SQL Schema for upgrading databases
 * Copyright (C) 2015-2021, Wazuh Inc.
 *
 * November, 2021.
 *
 * This program is a free software, you can redistribute it
 * and/or modify it under the terms of GPLv2.
*/

CREATE TABLE IF NOT EXISTS _belongs (
    id_agent INTEGER REFERENCES agent (id) ON DELETE CASCADE,
    id_group INTEGER REFERENCES `group` (id) ON DELETE CASCADE,
    priority INTEGER NOT NULL DEFAULT 0,
    UNIQUE (id_agent, priority),
    PRIMARY KEY (id_agent, id_group)
);

CREATE INDEX IF NOT EXISTS belongs_id_agent ON belongs (id_agent);
CREATE INDEX IF NOT EXISTS belongs_id_group ON belongs (id_group);

BEGIN;

INSERT INTO _belongs (id_agent, id_group, priority) SELECT id_agent, id_group, belongs.rowid FROM belongs WHERE id_agent IN (SELECT id FROM agent) AND id_group IN (SELECT id FROM `group`);

END;

DROP TABLE IF EXISTS belongs;
ALTER TABLE _belongs RENAME TO belongs;

CREATE TABLE IF NOT EXISTS _agent (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    ip TEXT,
    register_ip TEXT,
    internal_key TEXT,
    os_name TEXT,
    os_version TEXT,
    os_major TEXT,
    os_minor TEXT,
    os_codename TEXT,
    os_build TEXT,
    os_platform TEXT,
    os_uname TEXT,
    os_arch TEXT,
    version TEXT,
    config_sum TEXT,
    merged_sum TEXT,
    manager_host TEXT,
    node_name TEXT DEFAULT 'unknown',
    date_add INTEGER NOT NULL,
    last_keepalive INTEGER,
    `group` TEXT DEFAULT 'default',
    group_source TEXT NOT NULL CHECK (group_source IN ('manual', 'remote', 'undefined')) DEFAULT 'undefined',
    group_sync_with_master TEXT NOT NULL CHECK (group_sync_with_master IN ('synced', 'syncreq')) DEFAULT 'synced',
    sync_status TEXT NOT NULL CHECK (sync_status IN ('synced', 'syncreq')) DEFAULT 'synced',
    connection_status TEXT NOT NULL CHECK (connection_status IN ('pending', 'never_connected', 'active', 'disconnected')) DEFAULT 'never_connected',
    disconnection_time INTEGER DEFAULT 0
);

BEGIN;

INSERT INTO _agent (id, name, ip, register_ip, internal_key, os_name, os_version, os_major, os_minor, os_codename, os_build, os_platform, os_uname, os_arch, version, config_sum, merged_sum, manager_host, node_name, date_add, last_keepalive, `group`, sync_status, connection_status) SELECT id, name, ip, register_ip, internal_key, os_name, os_version, os_major, os_minor, os_codename, os_build, os_platform, os_uname, os_arch, version, config_sum, merged_sum, manager_host, node_name, date_add, last_keepalive, `group`, sync_status, connection_status FROM agent;

END;

DROP TABLE IF EXISTS agent;
ALTER TABLE _agent RENAME TO agent;
ALTER TABLE agent ADD COLUMN groups_hash TEXT default NULL;
CREATE INDEX IF NOT EXISTS agent_name ON agent (name);
CREATE INDEX IF NOT EXISTS agent_ip ON agent (ip);
CREATE INDEX IF NOT EXISTS agent_groups_hash ON agent (groups_hash);

UPDATE metadata SET value = '4' where key = 'db_version';
