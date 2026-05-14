use crate::migrations;
use rusqlite::Connection;
use std::path::{Path, PathBuf};

pub const PROJECT_DIR_NAME: &str = ".revdeck";
pub const DATABASE_FILE_NAME: &str = "project.sqlite";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectInfo {
    pub root_dir: PathBuf,
    pub db_path: PathBuf,
}

pub struct ProjectDatabase {
    info: ProjectInfo,
    connection: Connection,
}

impl ProjectDatabase {
    pub fn create_or_open(project_dir: impl AsRef<Path>) -> rusqlite::Result<Self> {
        let root_dir = project_dir.as_ref().to_path_buf();
        let revdeck_dir = root_dir.join(PROJECT_DIR_NAME);
        std::fs::create_dir_all(&revdeck_dir)
            .map_err(|err| rusqlite::Error::ToSqlConversionFailure(Box::new(err)))?;
        let db_path = revdeck_dir.join(DATABASE_FILE_NAME);
        let mut connection = Connection::open(&db_path)?;
        connection.execute_batch("PRAGMA foreign_keys = ON;")?;
        migrations::migrate(&mut connection)?;
        let info = ProjectInfo { root_dir, db_path };
        Ok(Self { info, connection })
    }

    pub fn open_existing(project_dir: impl AsRef<Path>) -> rusqlite::Result<Self> {
        let root_dir = project_dir.as_ref().to_path_buf();
        let db_path = root_dir.join(PROJECT_DIR_NAME).join(DATABASE_FILE_NAME);
        let mut connection = Connection::open(&db_path)?;
        connection.execute_batch("PRAGMA foreign_keys = ON;")?;
        migrations::migrate(&mut connection)?;
        let info = ProjectInfo { root_dir, db_path };
        Ok(Self { info, connection })
    }

    pub fn info(&self) -> &ProjectInfo {
        &self.info
    }

    pub fn connection(&self) -> &Connection {
        &self.connection
    }

    pub fn connection_mut(&mut self) -> &mut Connection {
        &mut self.connection
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrations::current_version;
    use tempfile::tempdir;

    #[test]
    fn project_reopen_preserves_database_path_and_schema() {
        let temp = tempdir().unwrap();
        let first = ProjectDatabase::create_or_open(temp.path()).unwrap();
        let db_path = first.info().db_path.clone();
        assert!(db_path.exists());
        assert_eq!(
            current_version(first.connection()).unwrap(),
            crate::migrations::SCHEMA_VERSION
        );
        drop(first);

        let second = ProjectDatabase::open_existing(temp.path()).unwrap();
        assert_eq!(second.info().db_path, db_path);
        assert_eq!(
            current_version(second.connection()).unwrap(),
            crate::migrations::SCHEMA_VERSION
        );
    }
}
