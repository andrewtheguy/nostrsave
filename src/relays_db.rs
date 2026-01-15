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

    let take = batch_size.min(total);
    let mut selected = Vec::with_capacity(take);
    for i in 0..take {
        let idx = (next_offset + i) % total;
        selected.push(relays[idx].clone());
    }

    // Advance offset by the number returned (wrap as needed)
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

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn seed_relays(dir: &Path, urls: &[&str]) -> Vec<String> {
        let urls: Vec<String> = urls.iter().map(|s| s.to_string()).collect();
        upsert_discovered_relays(dir, &urls).unwrap();
        urls
    }

    fn state_next_offset(dir: &Path) -> Option<i64> {
        let conn = Connection::open(relays_db_path(dir)).unwrap();
        conn.query_row(
            "SELECT next_offset FROM relay_selection_state WHERE id = 1",
            [],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .unwrap()
    }

    fn set_next_offset(dir: &Path, next_offset: i64) {
        let conn = Connection::open(relays_db_path(dir)).unwrap();
        conn.execute(
            "
            INSERT INTO relay_selection_state (id, next_offset, updated_at)
            VALUES (1, ?1, 0)
            ON CONFLICT(id) DO UPDATE SET next_offset = excluded.next_offset
            ",
            params![next_offset],
        )
        .unwrap();
    }

    fn shift_discovered_at_into_past(dir: &Path, delta_secs: i64) {
        let conn = Connection::open(relays_db_path(dir)).unwrap();
        conn.execute(
            "UPDATE discovered_relays SET discovered_at = discovered_at - ?1",
            params![delta_secs],
        )
        .unwrap();
    }

    fn count_last_used_set(dir: &Path) -> i64 {
        let conn = Connection::open(relays_db_path(dir)).unwrap();
        conn.query_row(
            "SELECT COUNT(*) FROM discovered_relays WHERE last_used_at IS NOT NULL",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap()
    }

    #[test]
    fn select_batch_wraps_and_returns_full_batch_when_possible() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();

        let relays = seed_relays(
            dir,
            &[
                "wss://r0.example.com",
                "wss://r1.example.com",
                "wss://r2.example.com",
                "wss://r3.example.com",
                "wss://r4.example.com",
                "wss://r5.example.com",
                "wss://r6.example.com",
                "wss://r7.example.com",
            ],
        );

        let batch1 = select_next_discovered_relay_batch(dir, 6).unwrap();
        assert_eq!(batch1, relays[0..6].to_vec());
        assert_eq!(state_next_offset(dir), Some(6));
        assert_eq!(count_last_used_set(dir), 6);

        let batch2 = select_next_discovered_relay_batch(dir, 6).unwrap();
        assert_eq!(
            batch2,
            vec![
                relays[6].clone(),
                relays[7].clone(),
                relays[0].clone(),
                relays[1].clone(),
                relays[2].clone(),
                relays[3].clone(),
            ]
        );
        assert_eq!(state_next_offset(dir), Some(4));
        assert_eq!(count_last_used_set(dir), 8);
    }

    #[test]
    fn select_batch_errors_when_batch_size_zero() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        seed_relays(dir, &["wss://r0.example.com"]);

        let err = select_next_discovered_relay_batch(dir, 0)
            .expect_err("expected batch_size=0 to error");
        assert!(err.to_string().contains("data_relays.batch_size must be >= 1"));
    }

    #[test]
    fn select_batch_errors_when_no_relays_present() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();

        let err = select_next_discovered_relay_batch(dir, 6)
            .expect_err("expected empty discovered_relays to error");
        assert!(err.to_string().contains("No discovered relays found"));
    }

    #[test]
    fn select_batch_wraps_large_next_offset() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let relays = seed_relays(
            dir,
            &[
                "wss://r0.example.com",
                "wss://r1.example.com",
                "wss://r2.example.com",
                "wss://r3.example.com",
                "wss://r4.example.com",
            ],
        );

        set_next_offset(dir, 999);
        let batch = select_next_discovered_relay_batch(dir, 3).unwrap();
        assert_eq!(
            batch,
            vec![relays[4].clone(), relays[0].clone(), relays[1].clone()]
        );
        assert_eq!(state_next_offset(dir), Some(2));
    }

    #[test]
    fn select_batch_treats_negative_next_offset_as_zero() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let relays = seed_relays(
            dir,
            &[
                "wss://r0.example.com",
                "wss://r1.example.com",
                "wss://r2.example.com",
            ],
        );

        set_next_offset(dir, -7);
        let batch = select_next_discovered_relay_batch(dir, 2).unwrap();
        assert_eq!(batch, relays[0..2].to_vec());
        assert_eq!(state_next_offset(dir), Some(2));
    }

    #[test]
    fn select_batch_updates_last_used_only_for_selected_relays() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let relays = seed_relays(
            dir,
            &[
                "wss://r0.example.com",
                "wss://r1.example.com",
                "wss://r2.example.com",
                "wss://r3.example.com",
                "wss://r4.example.com",
            ],
        );

        let batch = select_next_discovered_relay_batch(dir, 2).unwrap();
        assert_eq!(batch, relays[0..2].to_vec());
        assert_eq!(count_last_used_set(dir), 2);

        let conn = Connection::open(relays_db_path(dir)).unwrap();
        let mut stmt = conn
            .prepare("SELECT url FROM discovered_relays WHERE last_used_at IS NOT NULL ORDER BY position ASC")
            .unwrap();
        let rows = stmt.query_map([], |row| row.get::<_, String>(0)).unwrap();
        let used = rows.collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(used, relays[0..2].to_vec());
    }

    #[test]
    fn upsert_preserves_order_by_position() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let input = [
            "wss://z.example.com",
            "wss://a.example.com",
            "wss://m.example.com",
        ];

        seed_relays(dir, &input);
        let listed = list_discovered_relays(dir).unwrap();
        assert_eq!(
            listed,
            input.iter().map(|s| s.to_string()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn upsert_removes_relays_not_in_latest_discovery() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();

        seed_relays(
            dir,
            &[
                "wss://a.example.com",
                "wss://b.example.com",
                "wss://c.example.com",
            ],
        );

        // Make previous entries older so the next upsert run will delete missing rows deterministically.
        shift_discovered_at_into_past(dir, 10);

        upsert_discovered_relays(
            dir,
            &[
                "wss://c.example.com".to_string(),
                "wss://a.example.com".to_string(),
            ],
        )
        .unwrap();

        let listed = list_discovered_relays(dir).unwrap();
        assert_eq!(
            listed,
            vec![
                "wss://c.example.com".to_string(),
                "wss://a.example.com".to_string(),
            ]
        );
    }

    #[test]
    fn select_batch_is_capped_by_total_relays() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();

        let relays = seed_relays(
            dir,
            &[
                "wss://a.example.com",
                "wss://b.example.com",
                "wss://c.example.com",
                "wss://d.example.com",
            ],
        );

        let batch1 = select_next_discovered_relay_batch(dir, 6).unwrap();
        assert_eq!(batch1, relays);
        assert_eq!(state_next_offset(dir), Some(0));

        let batch2 = select_next_discovered_relay_batch(dir, 6).unwrap();
        assert_eq!(batch2, relays);
        assert_eq!(state_next_offset(dir), Some(0));
    }
}
