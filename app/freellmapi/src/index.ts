import './env.js';
import { createApp } from './app.js';
import { initDb } from './db/index.js';
import { startHealthChecker } from './services/health.js';

const PORT = process.env.PORT ?? 3001;
const HOST = process.env.HOST ?? '127.0.0.1';

async function main() {
  initDb();
  const app = createApp();

  app.listen(Number(PORT), HOST, () => {
    console.log(`Server running on http://${HOST}:${PORT}`);
    console.log(`Proxy endpoint: http://${HOST}:${PORT}/v1/chat/completions`);
    startHealthChecker();
  });
}

main().catch(console.error);
