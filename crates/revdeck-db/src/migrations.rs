use rusqlite::{Connection, OptionalExtension};
use std::collections::BTreeSet;

pub const SCHEMA_VERSION: i64 = 12;

pub const MIGRATION_0001: &str = include_str!("../migrations/0001_foundation.sql");
pub const MIGRATION_0002: &str = include_str!("../migrations/0002_binary_index.sql");
pub const MIGRATION_0003: &str = include_str!("../migrations/0003_function_radar.sql");
pub const MIGRATION_0004: &str = include_str!("../migrations/0004_analysis_memory_findings.sql");
pub const MIGRATION_0005: &str = include_str!("../migrations/0005_plugin_runs.sql");
pub const MIGRATION_0006: &str = include_str!("../migrations/0006_plugin_contributions.sql");
pub const MIGRATION_0007: &str = include_str!("../migrations/0007_native_cfg.sql");
pub const MIGRATION_0008: &str = include_str!("../migrations/0008_analysis_jobs.sql");
pub const MIGRATION_0009: &str = include_str!("../migrations/0009_trace_lab.sql");
pub const MIGRATION_0010: &str = include_str!("../migrations/0010_firmware_lab.sql");
pub const MIGRATION_0011: &str = include_str!("../migrations/0011_crash_lab.sql");
pub const MIGRATION_0012: &str = include_str!("../migrations/0012_protocol_lab.sql");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Migration {
    pub version: i64,
    pub name: &'static str,
    pub sql: &'static str,
}

pub const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        name: "foundation",
        sql: MIGRATION_0001,
    },
    Migration {
        version: 2,
        name: "binary_index",
        sql: MIGRATION_0002,
    },
    Migration {
        version: 3,
        name: "function_radar",
        sql: MIGRATION_0003,
    },
    Migration {
        version: 4,
        name: "analysis_memory_findings",
        sql: MIGRATION_0004,
    },
    Migration {
        version: 5,
        name: "plugin_runs",
        sql: MIGRATION_0005,
    },
    Migration {
        version: 6,
        name: "plugin_contributions",
        sql: MIGRATION_0006,
    },
    Migration {
        version: 7,
        name: "native_cfg",
        sql: MIGRATION_0007,
    },
    Migration {
        version: 8,
        name: "analysis_jobs",
        sql: MIGRATION_0008,
    },
    Migration {
        version: 9,
        name: "trace_lab",
        sql: MIGRATION_0009,
    },
    Migration {
        version: 10,
        name: "firmware_lab",
        sql: MIGRATION_0010,
    },
    Migration {
        version: 11,
        name: "crash_lab",
        sql: MIGRATION_0011,
    },
    Migration {
        version: 12,
        name: "protocol_lab",
        sql: MIGRATION_0012,
    },
];

pub fn migrate(connection: &mut Connection) -> rusqlite::Result<()> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        );",
    )?;

    let applied = applied_versions(connection)?;
    for migration in MIGRATIONS {
        if applied.contains(&migration.version) {
            continue;
        }

        let transaction = connection.transaction()?;
        transaction.execute_batch(migration.sql)?;
        transaction.execute(
            "INSERT INTO schema_migrations(version, name) VALUES (?1, ?2)",
            (migration.version, migration.name),
        )?;
        transaction.commit()?;
    }

    Ok(())
}

pub fn current_version(connection: &Connection) -> rusqlite::Result<i64> {
    connection
        .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
            row.get::<_, Option<i64>>(0)
        })
        .optional()
        .map(|value| value.flatten().unwrap_or(0))
}

fn applied_versions(connection: &Connection) -> rusqlite::Result<BTreeSet<i64>> {
    let mut statement = connection.prepare("SELECT version FROM schema_migrations")?;
    let versions = statement
        .query_map([], |row| row.get::<_, i64>(0))?
        .collect::<rusqlite::Result<BTreeSet<_>>>()?;
    Ok(versions)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrations_create_foundation_tables() {
        let mut connection = Connection::open_in_memory().unwrap();
        migrate(&mut connection).unwrap();

        let table_names: BTreeSet<String> = connection
            .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
            .unwrap()
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();

        for table in [
            "schema_migrations",
            "project_meta",
            "artifacts",
            "analysis_runs",
            "objects",
            "edges",
            "sections",
            "symbols",
            "functions",
            "strings",
            "imports",
            "xrefs",
            "score_reasons",
            "annotations",
            "annotation_evidence",
            "findings",
            "finding_evidence",
            "plugin_runs",
            "plugin_attributes",
            "plugin_diagnostics",
            "basic_blocks",
            "instructions",
            "cfg_edges",
            "analysis_jobs",
            "trace_sessions",
            "trace_events",
            "firmware_files",
            "crash_reports",
            "crash_frames",
            "protocol_samples",
            "protocol_messages",
            "protocol_fields",
        ] {
            assert!(table_names.contains(table), "missing table {table}");
        }
        assert_eq!(current_version(&connection).unwrap(), SCHEMA_VERSION);
    }

    #[test]
    fn migrations_are_idempotent() {
        let mut connection = Connection::open_in_memory().unwrap();
        migrate(&mut connection).unwrap();
        migrate(&mut connection).unwrap();

        let count: i64 = connection
            .query_row("SELECT COUNT(*) FROM schema_migrations", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, MIGRATIONS.len() as i64);
    }
}
