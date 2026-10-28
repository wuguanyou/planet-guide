// 載入 Node.js 內建的 SQLite 資料庫工具
const { DatabaseSync } = require("node:sqlite");

// 建立或開啟 users.db 資料庫
const db = new DatabaseSync("users.db");

// 建立 users 資料表；如果已存在，就不重複建立
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  )
`);

// 關閉資料庫
db.close();

console.log("資料庫和 users 資料表已建立！");