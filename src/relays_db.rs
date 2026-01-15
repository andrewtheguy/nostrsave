use rusqlite::{params, Connection, OptionalExtension};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const RELAYS_DB_FILENAME: &str = "data_relays.sqlite3";

fn unix_timestamp_secs() -> anyhow::Result<i64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| anyhow::anyhow!("system clock error: time is before Unix epoch ({})", e))?
        .as_secs() as i64)
}

pub fn relays_db_path(config_dir: &Path) -> PathBuf {
    config_dir.join(RELAYS_DB_FILENAME)
}

fn open_and_init(config_dir: &Path) -> anyhow::Result<Connection> {
    std::fs::create_dir_all(config_dir)?;
    let db_path = relays_db_path(config_dir);
    let conn = Connection::open(db_path)?;

    conn.execute_batch(
        "
        PRAGMA journal_mode = WAL;
        PRAGMA foreign_keys = ON;

        CREATE TABLE IF NOT EXISTS discovered_relays (
            url TEXT PRIMARY KEY,
            position INTEGER NOT NULL,
            discovered_at INTEGER NOT NULL,
            last_used_at INTEGER
        );

        CREATE TABLE IF NOT EXISTS relay_selection_state (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            next_offset INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );
        ",
    )?;

    Ok(conn)
}

pub fn upsert_discovered_relays(config_dir: &Path, ordered_urls: &[String]) -> anyhow::Result<()> {
    let mut conn = open_and_init(config_dir)?;
    let discovered_at = unix_timestamp_secs()?;

    let tx = conn.transaction()?;

    for (position, url) in ordered_urls.iter().enumerate() {
        tx.execute(
            "
            INSERT INTO discovered_relays (url, position, discovered_at)
            VALUES (?1, ?2, ?3)
            ON CONFLICT(url) DO UPDATE SET
                position = excluded.position,
                discovered_at = excluded.discovered_at
            ",
            params![url, position as i64, discovered_at],
        )?;
    }

    // Remove any relays not present in this discovery run
    tx.execute(
        "DELETE FROM discovered_relays WHERE discovered_at < ?1",
        params![discovered_at],
    )?;

    tx.commit()?;
    Ok(())
}

pub fn list_discovered_relays(config_dir: &Path) -> anyhow::Result<Vec<String>> {
    let conn = open_and_init(config_dir)?;
    let mut stmt = conn.prepare(
        "SELECT url FROM discovered_relays ORDER BY position ASC, url ASC",
    )?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

pub fn select_next_discovered_relay_batch(
    config_dir: &Path,
    batch_size: usize,
) -> anyhow::Result<Vec<String>> {
    if batch_size == 0 {
        return Err(anyhow::anyhow!("data_relays.batch_size must be >= 1"));
    }

    let mut conn = open_and_init(config_dir)?;
    let now = unix_timestamp_secs()?;

    let tx = conn.transaction()?;

    let relays: Vec<String> = {
        let mut stmt = tx.prepare(
            "SELECT url FROM discovered_relays ORDER BY position ASC, url ASC",
        )?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        let mut relays = Vec::new();
        for url in rows {
            relays.push(url?);
        }
        relays
    };

    if relays.is_empty() {
        return Err(anyhow::anyhow!(
            "No discovered relays found. Run `nostrsave discover-relays --relay-source index-relays` first."
        ));
    }

    let total = relays.len();
    let mut next_offset: usize = tx
        .query_row(
            "SELECT next_offset FROM relay_selection_state WHERE id = 1",
            [],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .map(|v| v.max(0) as usize)
        .unwrap_or(0);

    next_offset %= total;

    let remaining = total - next_offset;
    let take = remaining.min(batch_size);

    let selected: Vec<String> = relays[next_offset..next_offset + take].to_vec();

    // Advance offset (wrap after reaching the end; do not wrap within a single batch)
    let new_offset = (next_offset + take) % total;

    tx.execute(
        "
        INSERT INTO relay_selection_state (id, next_offset, updated_at)
        VALUES (1, ?1, ?2)
        ON CONFLICT(id) DO UPDATE SET
            next_offset = excluded.next_offset,
            updated_at = excluded.updated_at
        ",
        params![new_offset as i64, now],
    )?;

    for url in &selected {
        tx.execute(
            "UPDATE discovered_relays SET last_used_at = ?1 WHERE url = ?2",
            params![now, url],
        )?;
    }

    tx.commit()?;
    Ok(selected)
}
