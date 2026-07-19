import crypto from 'crypto';
import Database from 'better-sqlite3';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, describe, expect, it } from 'vitest';

import { rotateEncryptionKey } from '../../scripts/rotate-encryption-key.js';

const oldKey = '1'.repeat(64);
const newKey = '2'.repeat(64);
const wrongKey = '3'.repeat(64);
const workspaces: string[] = [];

function seal(plaintext: string, hexKey: string) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(hexKey, 'hex'), iv);
  let encrypted = cipher.update(plaintext, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return { encrypted, iv: iv.toString('hex'), authTag: cipher.getAuthTag().toString('hex') };
}

function open(row: { encrypted_key: string; iv: string; auth_tag: string }, hexKey: string): string {
  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    Buffer.from(hexKey, 'hex'),
    Buffer.from(row.iv, 'hex'),
  );
  decipher.setAuthTag(Buffer.from(row.auth_tag, 'hex'));
  let plaintext = decipher.update(row.encrypted_key, 'hex', 'utf8');
  plaintext += decipher.final('utf8');
  return plaintext;
}

function createDatabase() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'freellm-key-rotation-'));
  workspaces.push(directory);
  const databasePath = path.join(directory, 'freeapi.db');
  const db = new Database(databasePath);
  db.exec(
    [
      'CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);',
      'CREATE TABLE api_keys (',
      '  id INTEGER PRIMARY KEY AUTOINCREMENT,',
      '  encrypted_key TEXT NOT NULL,',
      '  iv TEXT NOT NULL,',
      '  auth_tag TEXT NOT NULL',
      ');',
    ].join('\n'),
  );
  const encrypted = seal('fictional-provider-key', oldKey);
  db.prepare("INSERT INTO settings (key, value) VALUES ('encryption_key', ?)").run(oldKey);
  db.prepare('INSERT INTO api_keys (encrypted_key, iv, auth_tag) VALUES (?, ?, ?)').run(
    encrypted.encrypted,
    encrypted.iv,
    encrypted.authTag,
  );
  db.close();
  return databasePath;
}

afterEach(() => {
  while (workspaces.length) {
    fs.rmSync(workspaces.pop()!, { recursive: true, force: true });
  }
});

describe('rotateEncryptionKey', () => {
  it('validates, re-encrypts, updates the fallback key, and rejects the retired key', () => {
    const databasePath = createDatabase();

    expect(rotateEncryptionKey({ databasePath, oldKey, newKey, dryRun: true })).toMatchObject({
      apiKeys: 1,
      dryRun: true,
      settingsKeyUpdated: false,
      oldKeyRejected: null,
    });

    const result = rotateEncryptionKey({ databasePath, oldKey, newKey });
    expect(result).toMatchObject({
      apiKeys: 1,
      dryRun: false,
      settingsKeyUpdated: true,
      oldKeyRejected: true,
    });

    const db = new Database(databasePath, { readonly: true });
    const row = db.prepare('SELECT encrypted_key, iv, auth_tag FROM api_keys WHERE id = 1').get() as {
      encrypted_key: string;
      iv: string;
      auth_tag: string;
    };
    expect(open(row, newKey)).toBe('fictional-provider-key');
    expect(() => open(row, oldKey)).toThrow();
    expect(db.prepare("SELECT value FROM settings WHERE key = 'encryption_key'").get()).toEqual({
      value: newKey,
    });
    db.close();
  });

  it('fails closed when the supplied current key cannot decrypt stored provider keys', () => {
    const databasePath = createDatabase();

    expect(() => rotateEncryptionKey({ databasePath, oldKey: wrongKey, newKey })).toThrow(
      /cannot be decrypted/,
    );

    const db = new Database(databasePath, { readonly: true });
    const row = db.prepare('SELECT encrypted_key, iv, auth_tag FROM api_keys WHERE id = 1').get() as {
      encrypted_key: string;
      iv: string;
      auth_tag: string;
    };
    expect(open(row, oldKey)).toBe('fictional-provider-key');
    db.close();
  });
});
