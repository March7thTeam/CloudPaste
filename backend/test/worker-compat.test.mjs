import assert from "node:assert/strict";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { Readable } from "node:stream";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { S3Client, ListObjectsV2Command } from "@aws-sdk/client-s3";
import { Miniflare, convertV4MiniflareOptions, Log, LogLevel } from "miniflare";

test("isolated Worker preserves authentication and offline S3 signing", { timeout: 60_000 }, async (t) => {
  let outboundRequests = 0;
  const mf = new Miniflare(convertV4MiniflareOptions({
    modules: true,
    scriptPath: fileURLToPath(new URL("../.test-build/worker.js", import.meta.url)),
    compatibilityDate: "2023-05-18",
    d1Databases: ["DB"],
    d1Persist: false,
    log: new Log(LogLevel.NONE),
    bindings: { ENCRYPTION_SECRET: randomBytes(32).toString("hex") },
    outboundService() {
      outboundRequests += 1;
      throw new Error("Network access is forbidden in the isolated Worker test");
    },
  }));

  try {
    const db = await mf.getD1Database("DB");
    // Seed an ephemeral account before initialization; never use the template's
    // default credentials, and keep all database state inside this test runtime.
    const username = "local-" + randomUUID();
    const password = randomBytes(24).toString("hex");
    await db.prepare(`CREATE TABLE admins (
      id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`).run();
    await db.prepare("INSERT INTO admins (id, username, password) VALUES (?, ?, ?)")
      .bind(randomUUID(), username, createHash("sha256").update(password).digest("hex")).run();

    const request = (path, init = {}) => mf.dispatchFetch("http://local.test" + path, init);
    const jsonRequest = (path, body, token) => request(path, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...(token ? { Authorization: "Bearer " + token } : {}) },
      body: JSON.stringify(body),
    });

    await t.test("public route initializes local D1", async () => {
      const response = await request("/api");
      assert.equal(response.status, 200);
      assert.deepEqual(await response.json(), { name: "CloudPaste API", version: "1.0.0", status: "ok" });
    });
    await t.test("CORS preflight remains available", async () => {
      const response = await request("/api/admin/login", {
        method: "OPTIONS",
        headers: { Origin: "https://client.invalid", "Access-Control-Request-Method": "POST" },
      });
      assert.equal(response.status, 204);
      assert.equal(response.headers.get("access-control-allow-origin"), "*");
    });
    await t.test("missing and invalid credentials remain rejected", async () => {
      assert.equal((await request("/api/admin/api-keys")).status, 401);
      assert.equal((await request("/api/admin/api-keys", { headers: { Authorization: "Bearer invalid" } })).status, 401);
      assert.equal((await jsonRequest("/api/admin/login", { username, password: "invalid" })).status, 401);
    });

    const login = await jsonRequest("/api/admin/login", { username, password });
    assert.equal(login.status, 200);
    const token = (await login.json()).data.token;
    assert.equal(typeof token, "string");
    await t.test("session token authorizes the original protected route", async () => {
      const response = await request("/api/test/admin-token", { headers: { Authorization: "Bearer " + token } });
      assert.equal(response.status, 200);
      assert.equal((await response.json()).success, true);
    });

    const created = await jsonRequest("/api/s3-configs", {
      name: "Isolated fixture", provider_type: "Other S3 Compatible",
      endpoint_url: "https://s3.invalid", bucket_name: "fixture-bucket",
      access_key_id: "fixture-only", secret_access_key: randomBytes(24).toString("hex"),
      region: "us-east-1", path_style: true,
    }, token);
    assert.equal(created.status, 200); // Existing API uses JSON code 201.
    const config = await created.json();
    assert.equal(config.code, 201);
    const configId = config.data.id;

    await t.test("upload signing still enforces authorization", async () => {
      assert.equal((await jsonRequest("/api/s3/presign", { s3_config_id: configId, filename: "fixture.txt" })).status, 403);
    });
    await t.test("S3 upload signature and file metadata are produced offline", async () => {
      const response = await jsonRequest("/api/s3/presign", {
        s3_config_id: configId, filename: "测试.txt", mimetype: "text/plain", size: 3,
      }, token);
      assert.equal(response.status, 200);
      const result = await response.json();
      assert.equal(result.success, true);
      const signed = new URL(result.data.upload_url);
      assert.equal(signed.hostname, "s3.invalid");
      assert.ok(decodeURIComponent(signed.pathname).startsWith("/fixture-bucket/"));
      assert.ok(decodeURIComponent(signed.pathname).endsWith("测试.txt"));
      assert.equal(signed.searchParams.get("X-Amz-Algorithm"), "AWS4-HMAC-SHA256");
      assert.equal(signed.searchParams.get("X-Amz-Expires"), "3600");
      assert.match(signed.searchParams.get("X-Amz-Signature"), /^[a-f0-9]{64}$/);
      const file = await db.prepare("SELECT filename, storage_path FROM files WHERE id = ?").bind(result.data.file_id).first();
      assert.equal(file.filename, "测试.txt");
      assert.equal(file.storage_path, result.data.storage_path);
    });
    await t.test("logout revokes the session", async () => {
      assert.equal((await jsonRequest("/api/admin/logout", {}, token)).status, 200);
      assert.equal((await request("/api/test/admin-token", { headers: { Authorization: "Bearer " + token } })).status, 401);
    });
    assert.equal(outboundRequests, 0);
  } finally {
    await mf.dispose();
  }
});

test("updated S3 transport parses a normal XML listing without network access", async () => {
  let requests = 0;
  const xml = '<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>fixture-bucket</Name><KeyCount>1</KeyCount><IsTruncated>false</IsTruncated><Contents><Key>one&amp;two.txt</Key><Size>3</Size></Contents></ListBucketResult>';
  const client = new S3Client({
    region: "us-east-1", endpoint: "https://s3.invalid", forcePathStyle: true,
    credentials: { accessKeyId: "fixture-only", secretAccessKey: "fixture-only" },
    requestHandler: {
      async handle(request) {
        requests += 1;
        assert.equal(request.hostname, "s3.invalid");
        return { response: { statusCode: 200, headers: { "content-type": "application/xml" }, body: Readable.from([xml]) } };
      },
    },
  });
  try {
    const result = await client.send(new ListObjectsV2Command({ Bucket: "fixture-bucket" }));
    assert.equal(result.Name, "fixture-bucket");
    assert.equal(result.Contents[0].Key, "one&two.txt");
    assert.equal(result.Contents[0].Size, 3);
    assert.equal(requests, 1);
  } finally {
    client.destroy();
  }
});
