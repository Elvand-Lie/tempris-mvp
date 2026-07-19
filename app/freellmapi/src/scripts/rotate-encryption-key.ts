import crypto from 'crypto';
import Database from 'better-sqlite3';
import fs from 'fs';
import path from 'path';
import { fileURLToPath, pathToFileURL } from 'url';

const ALGORITHM = 'aes-256-gcm';
const KEY_HEX_LENGTH = 64;

type EncryptedKeyRow = {
  id: number;
  encrypted_key: string;
  iv: string;
  auth_tag: string;
};

type RotationOptions = {
  databasePath: string;
  oldKey: string;
  newKey: string;
  dryRun?: boolean;
};

export type RotationResult = {
  apiKeys: number;
  dryRun: boolean;
  settingsKeyUpdated: boolean;
  oldKeyRejected: boolean | null;
};

function parseKey(value: string, label: string): Buffer {
  if (value.length !== KEY_HEX_LENGTH || !/^[0-9a-fA-F]+$/.test(value)) {
    throw new Error(label + ' must contain exactly 64 hexadecimal characters');
  }
  return Buffer.from(value, 'hex');
}

function decryptWithKey(row: EncryptedKeyRow, key: Buffer): string {
  const decipher = crypto.createDecipheriv(ALGORITHM, key, Buffer.from(row.iv, 'hex'));
  decipher.setAuthTag(Buffer.from(row.auth_tag, 'hex'));
  let plaintext = decipher.update(row.encrypted_key, 'hex', 'utf8');
  plaintext += decipher.final('utf8');
  return plaintext;
}

function encryptWithKey(plaintext: string, key: Buffer) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  let encrypted = cipher.update(plaintext, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return {
    encrypted,
    iv: iv.toString('hex'),
    authTag: cipher.getAuthTag().toString('hex'),
  };
}

function tableExists(db: Database.Database, table: string): boolean {
  return Boolean(
    db.prepare('SELECT 1 FROM sqlite_master WHERE type = ? AND name = ?').get('table', table),
  );
}

export function rotateEncryptionKey(options: RotationOptions): RotationResult {
  const oldKey = parseKey(options.oldKey, 'FREELLMAPI_OLD_ENCRYPTION_KEY');
  const newKey = parseKey(options.newKey, 'FREELLMAPI_NEW_ENCRYPTION_KEY');
  if (crypto.timingSafeEqual(oldKey, newKey)) {
    throw new Error('Replacement encryption key must differ from the current key');
  }

  const databasePath = path.resolve(options.databasePath);
  if (!fs.existsSync(databasePath)) {
    throw new Error('FreeLLMAPI database file does not exist');
  }

  const db = new Database(databasePath, {
    readonly: Boolean(options.dryRun),
    fileMustExist: true,
  });

  try {
    if (!tableExists(db, 'api_keys') || !tableExists(db, 'settings')) {
      throw new Error('FreeLLMAPI database is missing required api_keys or settings tables');
    }

    const rows = db.prepare(
      'SELECT id, encrypted_key, iv, auth_tag FROM api_keys ORDER BY id ASC',
    ).all() as EncryptedKeyRow[];
    const decrypted = rows.map((row) => {
      try {
        return { row, plaintext: decryptWithKey(row, oldKey) };
      } catch {
        throw new Error('A provider key cannot be decrypted with the supplied current key');
      }
    });

    if (options.dryRun) {
      return {
        apiKeys: rows.length,
        dryRun: true,
        settingsKeyUpdated: false,
        oldKeyRejected: null,
      };
    }

    const update = db.transaction(() => {
      const updateKey = db.prepare(
        'UPDATE api_keys SET encrypted_key = ?, iv = ?, auth_tag = ? WHERE id = ?',
      );
      for (const entry of decrypted) {
        const replacement = encryptWithKey(entry.plaintext, newKey);
        updateKey.run(replacement.encrypted, replacement.iv, replacement.authTag, entry.row.id);
      }
      db.prepare(
        "INSERT INTO settings (key, value) VALUES ('encryption_key', ?) " +
        'ON CONFLICT(key) DO UPDATE SET value = excluded.value',
      ).run(options.newKey);

      const updatedRows = db.prepare(
        'SELECT id, encrypted_key, iv, auth_tag FROM api_keys ORDER BY id ASC',
      ).all() as EncryptedKeyRow[];
      for (let index = 0; index < updatedRows.length; index += 1) {
        const updated = updatedRows[index];
        if (decryptWithKey(updated, newKey) !== decrypted[index].plaintext) {
          throw new Error('Replacement encryption key verification failed');
        }
        let oldKeyAccepted = false;
        try {
          decryptWithKey(updated, oldKey);
          oldKeyAccepted = true;
        } catch {
          // AES-GCM authentication failure is expected for the retired key.
        }
        if (oldKeyAccepted) {
          throw new Error('Retired encryption key still decrypts a provider key');
        }
      }
    });
    update();

    return {
      apiKeys: rows.length,
      dryRun: false,
      settingsKeyUpdated: true,
      oldKeyRejected: true,
    };
  } finally {
    db.close();
  }
}

function parseCommandLine(argv: string[]): { databasePath: string; dryRun: boolean } {
  const thisDir = path.dirname(fileURLToPath(import.meta.url));
  let databasePath = process.env.FREELLMAPI_DB_PATH || path.resolve(thisDir, '../../data/freeapi.db');
  let dryRun = false;

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--dry-run') {
      dryRun = true;
    } else if (arg === '--db-path') {
      const suppliedPath = argv[index + 1];
      if (!suppliedPath) {
        throw new Error('--db-path requires a value');
      }
      databasePath = suppliedPath;
      index += 1;
    } else {
      throw new Error('Unknown argument: ' + arg);
    }
  }
  return { databasePath, dryRun };
}

function runCli(): void {
  const options = parseCommandLine(process.argv.slice(2));
  const oldKey = process.env.FREELLMAPI_OLD_ENCRYPTION_KEY;
  const newKey = process.env.FREELLMAPI_NEW_ENCRYPTION_KEY;
  if (!oldKey || !newKey) {
    throw new Error(
      'FREELLMAPI_OLD_ENCRYPTION_KEY and FREELLMAPI_NEW_ENCRYPTION_KEY are required',
    );
  }
  const result = rotateEncryptionKey({ ...options, oldKey, newKey });
  console.log(JSON.stringify({ status: 'ok', ...result }));
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  try {
    runCli();
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown key rotation failure';
    console.error('Encryption key rotation failed: ' + message);
    process.exitCode = 1;
  }
}
