// 從 .env 讀取設定，例如 DATABASE_URL
require("dotenv").config();

const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");
const { randomBytes, scrypt, timingSafeEqual } = require("node:crypto");
const { promisify } = require("node:util");
const { Pool } = require("pg");

// 讓 scrypt 可以搭配 await 使用
const scryptAsync = promisify(scrypt);

// 讀取 Neon 的連線字串
if (!process.env.DATABASE_URL) {
  console.error("找不到 DATABASE_URL，請確認專案資料夾裡的 .env 檔案。");
  process.exit(1);
}

// 建立 PostgreSQL 連線
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

// 設定密碼雜湊功能
const PORT = process.env.PORT || 3000;

// 回傳 JSON 格式的訊息
function sendJson(res, statusCode, data) {
  res.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
  });
  res.end(JSON.stringify(data));
}

// 讀取瀏覽器送來的 JSON 資料
function readJson(req) {
  return new Promise((resolve, reject) => {
    let body = "";

    req.on("data", (chunk) => {
      body += chunk;

      // 避免接收過大的資料
      if (body.length > 100_000) {
        reject(new Error("資料太大"));
        req.destroy();
      }
    });

    req.on("end", () => {
      try {
        resolve(JSON.parse(body));
      } catch {
        reject(new Error("請傳送有效的 JSON"));
      }
    });

    req.on("error", reject);
  });
}

// 建立網站伺服器
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, "http://localhost");

  // 開啟首頁時送出 index.html
  if (req.method === "GET" && url.pathname === "/") {
    const html = fs.readFileSync(path.join(__dirname, "index.html"));

    res.writeHead(200, {
      "Content-Type": "text/html; charset=utf-8",
    });

    return res.end(html);
  }

  // 確認網站伺服器和資料庫都能連線
  if (req.method === "GET" && url.pathname === "/api/status") {
    try {
      await pool.query("SELECT 1");

      return sendJson(res, 200, {
        message: "伺服器和資料庫都正常",
      });
    } catch (error) {
      console.error("資料庫連線錯誤：", error);

      return sendJson(res, 503, {
        message: "資料庫連線失敗，請檢查設定",
      });
    }
  }

  // 註冊帳號
  if (req.method === "POST" && url.pathname === "/api/register") {
    try {
      const { username, password } = await readJson(req);
      const cleanUsername = String(username || "").trim();

      if (cleanUsername.length < 3 || cleanUsername.length > 30) {
        return sendJson(res, 400, {
          message: "帳號長度需為 3 到 30 個字元",
        });
      }

      if (typeof password !== "string" || password.length < 8) {
        return sendJson(res, 400, {
          message: "密碼至少需要 8 個字元",
        });
      }

      // 隨機產生鹽值，再將密碼轉成雜湊
      const salt = randomBytes(16).toString("hex");

      const hash = await scryptAsync(password, salt, 64, {
        N: 2 ** 14,
        r: 8,
        p: 1,
        maxmem: 64 * 1024 * 1024,
      });

      const passwordHash = `${salt}:${hash.toString("hex")}`;

      // $1、$2 是 PostgreSQL 的參數位置
      await pool.query(
        "INSERT INTO users (username, password_hash) VALUES ($1, $2)",
        [cleanUsername, passwordHash]
      );

      return sendJson(res, 201, {
        message: "註冊成功",
      });
    } catch (error) {
      // 23505 代表違反唯一值限制，也就是帳號已存在
      if (error.code === "23505") {
        return sendJson(res, 409, {
          message: "這個帳號已經註冊",
        });
      }

      console.error("註冊錯誤：", error);

      return sendJson(res, 500, {
        message: "註冊時發生錯誤",
      });
    }
  }

  // 登入帳號
  if (req.method === "POST" && url.pathname === "/api/login") {
    try {
      const { username, password } = await readJson(req);
      const cleanUsername = String(username || "").trim();

      const result = await pool.query(
        "SELECT password_hash FROM users WHERE username = $1",
        [cleanUsername]
      );

      const user = result.rows[0];

      if (!user || typeof password !== "string") {
        return sendJson(res, 401, {
          message: "帳號或密碼錯誤",
        });
      }

      // 從資料庫取出原本儲存的鹽值和雜湊
      const [salt, savedHashHex] = user.password_hash.split(":");
      const savedHash = Buffer.from(savedHashHex, "hex");

      // 用相同鹽值計算這次輸入的密碼
      const enteredHash = await scryptAsync(password, salt, 64, {
        N: 2 ** 14,
        r: 8,
        p: 1,
        maxmem: 64 * 1024 * 1024,
      });

      // 安全地比較兩個雜湊
      if (!timingSafeEqual(savedHash, enteredHash)) {
        return sendJson(res, 401, {
          message: "帳號或密碼錯誤",
        });
      }

      return sendJson(res, 200, {
        message: "登入成功",
      });
    } catch (error) {
      console.error("登入錯誤：", error);

      return sendJson(res, 500, {
        message: "登入時發生錯誤",
      });
    }
  }

  // 其他網址回傳找不到
  return sendJson(res, 404, {
    message: "找不到這個網址",
  });
});

// 建立 Neon 裡的 users 資料表
async function startServer() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
      username VARCHAR(30) NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  server.listen(PORT, "0.0.0.0", () => {
    console.log(`伺服器已啟動，連接埠：${PORT}`);
  });
}

// 如果連不上 Neon，就在 PowerShell 顯示錯誤
startServer().catch((error) => {
  console.error("伺服器啟動失敗，請檢查 .env 連線字串。");
  console.error(error.message);
  process.exit(1);
});