import { request } from "@playwright/test";

/**
 * Global setup for the Sentinel IDS e2e suite.
 *
 * This setup does NOT start any servers: it assumes the stack is already
 * running (see README). It only logs the assumption and performs a non-fatal
 * reachability probe against the frontend so misconfiguration shows up early.
 */
export default async function globalSetup(): Promise<void> {
  const baseURL = process.env.E2E_BASE_URL ?? "http://localhost:5173";

  console.log(
    `[e2e] Global setup: assuming the Sentinel IDS stack is already running at ${baseURL}.`,
  );
  console.log(
    "[e2e] Start it with: docker compose -f infra/docker-compose.yml up -d --wait postgres redis backend frontend",
  );

  try {
    const probe = await request.newContext({ baseURL });
    const response = await probe.get("/", { timeout: 3_000 });
    if (!response.ok()) {
      console.warn(
        `[e2e] WARNING: frontend responded with HTTP ${response.status()} (expected 200). ` +
          "The stack may not be ready yet.",
      );
    }
    await probe.dispose();
  } catch {
    console.warn(
      `[e2e] WARNING: frontend at ${baseURL} is not reachable. ` +
        "Make sure the stack is running before running the suite.",
    );
  }
}
