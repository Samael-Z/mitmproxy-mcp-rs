//! SQLite 抓包存储（rusqlite，bundled）。线程安全：Arc<Mutex<Connection>>。

use std::sync::{Arc, Mutex};

use anyhow::Result;
use rusqlite::{params, Connection};

use crate::model::FlowRow;

#[derive(Clone)]
pub struct Store {
    conn: Arc<Mutex<Connection>>,
}

fn headers_to_json(h: &[(String, String)]) -> String {
    serde_json::to_string(h).unwrap_or_else(|_| "[]".into())
}

fn headers_from_json(s: Option<String>) -> Vec<(String, String)> {
    s.and_then(|s| serde_json::from_str::<Vec<(String, String)>>(&s).ok())
        .unwrap_or_default()
}

impl Store {
    pub fn open(path: &str) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS flows (
                id TEXT PRIMARY KEY,
                seq INTEGER,
                url TEXT,
                host TEXT,
                method TEXT,
                status INTEGER,
                req_headers TEXT,
                req_body TEXT,
                resp_headers TEXT,
                resp_body TEXT,
                timestamp REAL,
                size INTEGER
            );
            CREATE INDEX IF NOT EXISTS idx_seq ON flows(seq);
            CREATE INDEX IF NOT EXISTS idx_host ON flows(host);
            CREATE INDEX IF NOT EXISTS idx_method ON flows(method);
            "#,
        )?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    pub fn save_flow(&self, f: &FlowRow) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        // 复用已存在 seq，否则取 max+1
        let seq: i64 =
            match conn.query_row("SELECT seq FROM flows WHERE id = ?1", [&f.id], |r| r.get(0)) {
                Ok(s) => s,
                Err(_) => {
                    conn.query_row("SELECT COALESCE(MAX(seq),0)+1 FROM flows", [], |r| r.get(0))?
                }
            };
        conn.execute(
            r#"INSERT INTO flows
               (id, seq, url, host, method, status, req_headers, req_body, resp_headers, resp_body, timestamp, size)
               VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)
               ON CONFLICT(id) DO UPDATE SET
                 url=excluded.url, host=excluded.host, method=excluded.method, status=excluded.status,
                 req_headers=excluded.req_headers, req_body=excluded.req_body,
                 resp_headers=excluded.resp_headers, resp_body=excluded.resp_body, size=excluded.size"#,
            params![
                f.id,
                seq,
                f.url,
                f.host,
                f.method,
                f.status,
                headers_to_json(&f.req_headers),
                f.req_body,
                headers_to_json(&f.resp_headers),
                f.resp_body,
                f.timestamp,
                f.size,
            ],
        )?;
        Ok(seq)
    }

    fn row_to_flow(row: &rusqlite::Row) -> rusqlite::Result<FlowRow> {
        Ok(FlowRow {
            id: row.get("id")?,
            seq: row.get("seq")?,
            url: row.get("url")?,
            host: row.get("host")?,
            method: row.get("method")?,
            status: row.get("status")?,
            req_headers: headers_from_json(row.get("req_headers")?),
            req_body: row.get("req_body")?,
            resp_headers: headers_from_json(row.get("resp_headers")?),
            resp_body: row.get("resp_body")?,
            timestamp: row.get("timestamp")?,
            size: row.get("size")?,
        })
    }

    /// 按 seq（纯数字）/ 完整 id / 短 id 前缀取一条。
    pub fn get(&self, flow_id: &str) -> Option<FlowRow> {
        let conn = self.conn.lock().unwrap();
        if let Ok(seq) = flow_id.parse::<i64>() {
            if let Ok(f) = conn.query_row("SELECT * FROM flows WHERE seq = ?1", [seq], |r| {
                Self::row_to_flow(r)
            }) {
                return Some(f);
            }
        }
        if let Ok(f) = conn.query_row(
            "SELECT * FROM flows WHERE id = ?1",
            [flow_id],
            Self::row_to_flow,
        ) {
            return Some(f);
        }
        conn.query_row(
            "SELECT * FROM flows WHERE id LIKE ?1 ORDER BY seq LIMIT 1",
            [format!("{flow_id}%")],
            Self::row_to_flow,
        )
        .ok()
    }

    pub fn summary(
        &self,
        limit: i64,
        domain: Option<&str>,
        method: Option<&str>,
    ) -> Vec<serde_json::Value> {
        let rows = self.query_filtered(domain, method, None, None, limit);
        rows.into_iter()
            .map(|f| {
                serde_json::json!({
                    "id": f.id,
                    "seq": f.seq,
                    "method": f.method,
                    "status": f.status,
                    "url": f.url,
                    "content_type": f.content_type(),
                    "size": f.size,
                })
            })
            .collect()
    }

    pub fn search(
        &self,
        query: Option<&str>,
        domain: Option<&str>,
        method: Option<&str>,
        status: Option<i64>,
        limit: i64,
    ) -> Vec<serde_json::Value> {
        let rows = self.query_filtered(domain, method, status, query, limit);
        rows.into_iter()
            .map(|f| {
                serde_json::json!({
                    "id": f.id, "seq": f.seq, "method": f.method,
                    "status": f.status, "url": f.url,
                })
            })
            .collect()
    }

    fn query_filtered(
        &self,
        domain: Option<&str>,
        method: Option<&str>,
        status: Option<i64>,
        query: Option<&str>,
        limit: i64,
    ) -> Vec<FlowRow> {
        let conn = self.conn.lock().unwrap();
        let mut sql = String::from("SELECT * FROM flows WHERE 1=1");
        let mut args: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        if let Some(d) = domain {
            sql.push_str(" AND host LIKE ?");
            args.push(Box::new(format!("%{d}%")));
        }
        if let Some(m) = method {
            sql.push_str(" AND method = ?");
            args.push(Box::new(m.to_uppercase()));
        }
        if let Some(s) = status {
            sql.push_str(" AND status = ?");
            args.push(Box::new(s));
        }
        if let Some(q) = query {
            sql.push_str(
                " AND (url LIKE ? OR req_body LIKE ? OR resp_body LIKE ? OR req_headers LIKE ?)",
            );
            let wc = format!("%{q}%");
            for _ in 0..4 {
                args.push(Box::new(wc.clone()));
            }
        }
        sql.push_str(" ORDER BY seq DESC LIMIT ?");
        args.push(Box::new(limit));

        let params: Vec<&dyn rusqlite::ToSql> = args.iter().map(|b| b.as_ref()).collect();
        let mut stmt = match conn.prepare(&sql) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let iter = stmt.query_map(params.as_slice(), Self::row_to_flow);
        match iter {
            Ok(it) => it.filter_map(|r| r.ok()).collect(),
            Err(_) => Vec::new(),
        }
    }

    pub fn all(&self, limit: Option<i64>) -> Vec<FlowRow> {
        let conn = self.conn.lock().unwrap();
        let sql = match limit {
            Some(_) => "SELECT * FROM flows ORDER BY seq DESC LIMIT ?1",
            None => "SELECT * FROM flows ORDER BY seq DESC",
        };
        let mut stmt = match conn.prepare(sql) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let mapper = |r: &rusqlite::Row| Self::row_to_flow(r);
        let res = match limit {
            Some(l) => stmt
                .query_map([l], mapper)
                .map(|it| it.filter_map(|r| r.ok()).collect()),
            None => stmt
                .query_map([], mapper)
                .map(|it| it.filter_map(|r| r.ok()).collect()),
        };
        res.unwrap_or_default()
    }

    pub fn count(&self) -> i64 {
        let conn = self.conn.lock().unwrap();
        conn.query_row("SELECT COUNT(*) FROM flows", [], |r| r.get(0))
            .unwrap_or(0)
    }

    /// 导出全部 flow 为 JSON 数组文件。
    pub fn export_json(&self, path: &str) -> Result<usize> {
        let rows = self.all(None);
        let n = rows.len();
        std::fs::write(path, serde_json::to_string_pretty(&rows)?)?;
        Ok(n)
    }

    /// 从 JSON 数组文件导入 flow（append=false 先清空）。
    pub fn import_json(&self, path: &str, append: bool) -> Result<usize> {
        let text = std::fs::read_to_string(path)?;
        let rows: Vec<FlowRow> = serde_json::from_str(&text)?;
        if !append {
            self.clear();
        }
        let mut n = 0;
        for f in &rows {
            if self.save_flow(f).is_ok() {
                n += 1;
            }
        }
        Ok(n)
    }

    pub fn clear(&self) -> i64 {
        let conn = self.conn.lock().unwrap();
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM flows", [], |r| r.get(0))
            .unwrap_or(0);
        let _ = conn.execute("DELETE FROM flows", []);
        n
    }
}
