import crypto from "crypto";
import dns from "dns";
import net from "net";
import { Queue, Worker, type ConnectionOptions, Job } from "bullmq";
import { v4 as uuidv4 } from "uuid";
import { db as prisma } from "../db";
import { config } from "../config";
import { logger } from "../logger";

export const WEBHOOK_QUEUE_NAME = "outbound-webhooks";
export const DEFAULT_WEBHOOK_TIMEOUT_MS = 5000;

export interface WebhookDeliveryJobData {
  endpointId: string;
  eventId: string;
  eventType: string;
  payload: Record<string, unknown>;
  timestamp: number;
}

export interface WebhookEndpointCreateInput {
  url: string;
  secret?: string;
  eventTypes: string[];
  active?: boolean;
}

export interface WebhookEndpointUpdateInput {
  url?: string;
  secret?: string;
  eventTypes?: string[];
  active?: boolean;
}

/**
 * Checks whether an IPv4 address belongs to a private, loopback, link-local,
 * multicast, broadcast, or reserved range.
 */
export function isPrivateOrReservedIPv4(ip: string): boolean {
  const parts = ip.split(".").map((part) => parseInt(part, 10));
  if (parts.length !== 4 || parts.some((p) => isNaN(p) || p < 0 || p > 255)) {
    return true; // Malformed IPv4 treated as unsafe
  }

  const [a, b] = parts;

  // 0.0.0.0/8 (Current network / default route)
  if (a === 0) return true;

  // 10.0.0.0/8 (Private-Use Networks, RFC 1918)
  if (a === 10) return true;

  // 127.0.0.0/8 (Loopback, RFC 1122)
  if (a === 127) return true;

  // 169.254.0.0/16 (Link-Local, RFC 3927 - AWS/cloud metadata e.g. 169.254.169.254)
  if (a === 169 && b === 254) return true;

  // 172.16.0.0/12 (Private-Use Networks, RFC 1918)
  if (a === 172 && b >= 16 && b <= 31) return true;

  // 192.168.0.0/16 (Private-Use Networks, RFC 1918)
  if (a === 192 && b === 168) return true;

  // 100.64.0.0/10 (Shared Address Space / CGNAT, RFC 6598)
  if (a === 100 && b >= 64 && b <= 127) return true;

  // 192.0.0.0/24 (IETF Protocol Assignments)
  if (a === 192 && b === 0 && parts[2] === 0) return true;

  // 192.0.2.0/24 (TEST-NET-1, documentation)
  if (a === 192 && b === 0 && parts[2] === 2) return true;

  // 198.18.0.0/15 (Benchmarking)
  if (a === 198 && (b === 18 || b === 19)) return true;

  // 198.51.100.0/24 (TEST-NET-2)
  if (a === 198 && b === 51 && parts[2] === 100) return true;

  // 203.0.113.0/24 (TEST-NET-3)
  if (a === 203 && b === 0 && parts[2] === 113) return true;

  // 224.0.0.0/4 (Multicast, RFC 5771)
  if (a >= 224 && a <= 239) return true;

  // 240.0.0.0/4 (Reserved / Future Use, RFC 1112)
  if (a >= 240) return true;

  return false;
}

/**
 * Checks whether an IPv6 address belongs to a loopback, unique local (fc00::/7),
 * link-local (fe80::/10), IPv4-mapped, or reserved range.
 */
export function isPrivateOrReservedIPv6(ip: string): boolean {
  const normalized = ip.toLowerCase().trim();

  // Loopback (::1) or Unspecified (::)
  if (normalized === "::1" || normalized === "::" || /^0*(:0*)*:1$/.test(normalized)) {
    return true;
  }

  // IPv4-mapped IPv6 (::ffff:192.168.1.1 or ::ffff:c0a8:0101)
  if (normalized.startsWith("::ffff:") || normalized.includes(":ffff:")) {
    const parts = normalized.split(":");
    const lastPart = parts[parts.length - 1];
    if (lastPart.includes(".")) {
      return isPrivateOrReservedIPv4(lastPart);
    }
    // Hex encoded IPv4
    const secondLast = parts[parts.length - 2];
    if (secondLast && lastPart) {
      const hex = secondLast.padStart(4, "0") + lastPart.padStart(4, "0");
      if (hex.length === 8) {
        const a = parseInt(hex.slice(0, 2), 16);
        const b = parseInt(hex.slice(2, 4), 16);
        const c = parseInt(hex.slice(4, 6), 16);
        const d = parseInt(hex.slice(6, 8), 16);
        return isPrivateOrReservedIPv4(`${a}.${b}.${c}.${d}`);
      }
    }
    return true;
  }

  // Unique Local Address (ULA): fc00::/7 (fc00... or fd00...)
  if (/^f[cd][0-9a-f]{2}:/i.test(normalized)) {
    return true;
  }

  // Link-Local: fe80::/10 (fe8..., fe9..., fea..., feb...)
  if (/^fe[89ab][0-9a-f]:/i.test(normalized)) {
    return true;
  }

  // Multicast: ff00::/8
  if (/^ff[0-9a-f]{2}:/i.test(normalized)) {
    return true;
  }

  // Documentation / discard: 2001:db8::/32, 100::/64
  if (normalized.startsWith("2001:db8:") || normalized.startsWith("100:")) {
    return true;
  }

  return false;
}

/**
 * Master IP guard for SSRF protection: evaluates whether an address is private,
 * loopback, link-local, multicast, or reserved in either IPv4 or IPv6.
 */
export function isBlockedIp(ip: string): boolean {
  const ipType = net.isIP(ip);
  if (ipType === 4) {
    return isPrivateOrReservedIPv4(ip);
  }
  if (ipType === 6) {
    return isPrivateOrReservedIPv6(ip);
  }
  return false;
}

/**
 * Validates a target URL against SSRF attacks:
 * 1. Must use https: protocol strictly (no http, ftp, file, etc.).
 * 2. Hostname cannot be localhost, a dotless hostname, or private TLDs.
 * 3. Resolves DNS records and verifies that no returned A or AAAA address is private/reserved.
 */
export async function validateWebhookUrl(rawUrl: string): Promise<URL> {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new Error(`Invalid webhook URL: "${rawUrl}"`);
  }

  if (parsed.protocol !== "https:") {
    throw new Error(
      `SSRF validation failed: webhook URLs must strictly use https: protocol, received "${parsed.protocol}"`
    );
  }

  const hostname = parsed.hostname.toLowerCase();

  // Block obvious loopback/internal hosts
  if (
    hostname === "localhost" ||
    hostname.endsWith(".localhost") ||
    hostname.endsWith(".local") ||
    hostname.endsWith(".internal") ||
    hostname.endsWith(".lan") ||
    hostname.endsWith(".corp") ||
    hostname.endsWith(".home")
  ) {
    throw new Error(`SSRF validation failed: blocked host "${hostname}"`);
  }

  // Check if hostname is an IP literal
  if (isBlockedIp(hostname)) {
    throw new Error(`SSRF validation failed: blocked IP address "${hostname}"`);
  }

  // Resolve hostname via DNS to prevent DNS rebinding to internal resources
  try {
    const addresses = await dns.promises.lookup(hostname, { all: true });
    if (!addresses || addresses.length === 0) {
      throw new Error(`SSRF validation failed: could not resolve DNS for "${hostname}"`);
    }

    for (const record of addresses) {
      if (isBlockedIp(record.address)) {
        throw new Error(
          `SSRF validation failed: host "${hostname}" resolved to blocked address "${record.address}"`
        );
      }
    }
  } catch (err: unknown) {
    if (err instanceof Error && err.message.startsWith("SSRF validation failed")) {
      throw err;
    }
    throw new Error(`SSRF validation failed: DNS lookup error for "${hostname}": ${(err as Error).message}`);
  }

  return parsed;
}

/**
 * Computes the HMAC-SHA256 signature over `${timestamp}.${body}` using the endpoint secret.
 */
export function generateWebhookSignature(
  secret: string,
  timestamp: number,
  body: string
): string {
  const payload = `${timestamp}.${body}`;
  return crypto.createHmac("sha256", secret).update(payload, "utf8").digest("hex");
}

/**
 * Verifies that the provided HMAC-SHA256 signature matches the expected signature.
 */
export function verifyWebhookSignature(
  secret: string,
  timestamp: number,
  body: string,
  signature: string
): boolean {
  const expected = generateWebhookSignature(secret, timestamp, body);
  try {
    return crypto.timingSafeEqual(
      Buffer.from(signature, "hex"),
      Buffer.from(expected, "hex")
    );
  } catch {
    return false;
  }
}

function getRedisConnection(): ConnectionOptions {
  try {
    const parsed = new URL(config.REDIS_URL);
    return {
      host: parsed.hostname,
      port: Number(parsed.port || 6379),
      username: parsed.username || undefined,
      password: parsed.password || undefined,
      maxRetriesPerRequest: null,
    };
  } catch {
    return {
      host: "127.0.0.1",
      port: 6379,
      maxRetriesPerRequest: null,
    };
  }
}

let webhookQueue: Queue<WebhookDeliveryJobData> | null = null;
let webhookWorker: Worker<WebhookDeliveryJobData> | null = null;

export function getWebhookQueue(): Queue<WebhookDeliveryJobData> {
  if (!webhookQueue) {
    webhookQueue = new Queue<WebhookDeliveryJobData>(WEBHOOK_QUEUE_NAME, {
      connection: getRedisConnection(),
      defaultJobOptions: {
        attempts: 5,
        backoff: {
          type: "exponential",
          delay: 1000,
        },
        removeOnComplete: 1000,
        removeOnFail: 5000,
      },
    });
  }
  return webhookQueue;
}

/**
 * Performs a single secure HTTP delivery of a webhook event:
 * - Re-evaluates SSRF guard before dispatch
 * - Enforces redirect: 'error' (no redirects allowed)
 * - Sets request timeout (5s default)
 * - Signs request with HMAC-SHA256 and sets idempotency event ID headers
 */
export async function executeWebhookDelivery(
  url: string,
  secret: string,
  eventId: string,
  eventType: string,
  payload: Record<string, unknown>,
  timestamp: number = Date.now(),
  timeoutMs: number = DEFAULT_WEBHOOK_TIMEOUT_MS
): Promise<{ statusCode: number; responseBody: string }> {
  // Validate SSRF right before the network request
  await validateWebhookUrl(url);

  const bodyString = JSON.stringify({
    id: eventId,
    event: eventType,
    timestamp,
    data: payload,
  });

  const signature = generateWebhookSignature(secret, timestamp, bodyString);

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Boxmeout-Signature": `t=${timestamp},v1=${signature}`,
        "X-Boxmeout-Event": eventType,
        "X-Boxmeout-Delivery": eventId,
        "X-Boxmeout-Timestamp": String(timestamp),
        "User-Agent": "Boxmeout-Webhook-Delivery/1.0",
      },
      body: bodyString,
      redirect: "error", // Strictly block redirects (SSRF defense)
      signal: controller.signal,
    });

    const text = await res.text();
    const truncatedBody = text.slice(0, 2048);

    if (!res.ok) {
      throw new Error(`Webhook endpoint returned HTTP status ${res.status}: ${truncatedBody}`);
    }

    return { statusCode: res.status, responseBody: truncatedBody };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Initializes the BullMQ worker for the outbound webhook delivery queue.
 */
export function startWebhookWorker(): Worker<WebhookDeliveryJobData> {
  if (webhookWorker) {
    return webhookWorker;
  }

  webhookWorker = new Worker<WebhookDeliveryJobData>(
    WEBHOOK_QUEUE_NAME,
    async (job: Job<WebhookDeliveryJobData>) => {
      const { endpointId, eventId, eventType, payload, timestamp } = job.data;
      const attempt = job.attemptsMade + 1;

      const endpoint = await prisma.webhookEndpoint.findUnique({
        where: { id: endpointId },
      });

      if (!endpoint || !endpoint.active) {
        logger.info({ endpointId, eventId }, "Webhook endpoint deleted or inactive; skipping job");
        return;
      }

      try {
        const { statusCode, responseBody } = await executeWebhookDelivery(
          endpoint.url,
          endpoint.secret,
          eventId,
          eventType,
          payload,
          timestamp
        );

        await prisma.webhookDeliveryLog.create({
          data: {
            endpointId,
            eventId,
            eventType,
            payload: payload as any,
            statusCode,
            responseBody,
            attempt,
            deliveredAt: new Date(),
          },
        });

        logger.info({ endpointId, eventId, eventType, attempt, statusCode }, "Webhook delivery succeeded");
      } catch (err: unknown) {
        const errorMsg = (err as Error).message || String(err);

        await prisma.webhookDeliveryLog.create({
          data: {
            endpointId,
            eventId,
            eventType,
            payload: payload as any,
            error: errorMsg,
            attempt,
          },
        });

        logger.warn({ endpointId, eventId, eventType, attempt, error: errorMsg }, "Webhook delivery attempt failed");
        throw err; // Trigger BullMQ exponential retry
      }
    },
    {
      connection: getRedisConnection(),
      concurrency: 5,
    }
  );

  webhookWorker.on("error", (err) => {
    logger.error({ err }, "Webhook worker error");
  });

  return webhookWorker;
}

export async function stopWebhookWorker(): Promise<void> {
  if (webhookWorker) {
    await webhookWorker.close();
    webhookWorker = null;
  }
  if (webhookQueue) {
    await webhookQueue.close();
    webhookQueue = null;
  }
}

// ---------------------------------------------------------------------------
// Endpoint Management Service Functions
// ---------------------------------------------------------------------------

export async function createWebhookEndpoint(input: WebhookEndpointCreateInput) {
  await validateWebhookUrl(input.url);

  const secret = input.secret && input.secret.trim().length >= 16
    ? input.secret.trim()
    : `whsec_${crypto.randomBytes(24).toString("hex")}`;

  return prisma.webhookEndpoint.create({
    data: {
      url: input.url,
      secret,
      eventTypes: input.eventTypes,
      active: input.active !== undefined ? input.active : true,
    },
  });
}

export async function listWebhookEndpoints(options?: { active?: boolean }) {
  const where: any = {};
  if (options?.active !== undefined) {
    where.active = options.active;
  }

  return prisma.webhookEndpoint.findMany({
    where,
    orderBy: { createdAt: "desc" },
    include: {
      _count: {
        select: { deliveries: true },
      },
    },
  });
}

export async function getWebhookEndpoint(id: string) {
  return prisma.webhookEndpoint.findUnique({
    where: { id },
    include: {
      deliveries: {
        take: 20,
        orderBy: { createdAt: "desc" },
      },
    },
  });
}

export async function updateWebhookEndpoint(id: string, input: WebhookEndpointUpdateInput) {
  if (input.url) {
    await validateWebhookUrl(input.url);
  }

  const data: any = {};
  if (input.url !== undefined) data.url = input.url;
  if (input.secret !== undefined) data.secret = input.secret;
  if (input.eventTypes !== undefined) data.eventTypes = input.eventTypes;
  if (input.active !== undefined) data.active = input.active;

  return prisma.webhookEndpoint.update({
    where: { id },
    data,
  });
}

export async function deleteWebhookEndpoint(id: string) {
  return prisma.webhookEndpoint.delete({
    where: { id },
  });
}

/**
 * Dispatches an event to all active endpoints subscribed to eventType or "*".
 */
export async function dispatchMarketEvent(
  eventType: string,
  payload: Record<string, unknown>,
  customEventId?: string
): Promise<string[]> {
  const eventId = customEventId || `evt_${uuidv4()}`;
  const timestamp = Date.now();

  const endpoints = await prisma.webhookEndpoint.findMany({
    where: {
      active: true,
      OR: [
        { eventTypes: { has: eventType } },
        { eventTypes: { has: "*" } },
      ],
    },
  });

  if (endpoints.length === 0) {
    return [];
  }

  const queue = getWebhookQueue();
  const jobIds: string[] = [];

  for (const ep of endpoints) {
    const job = await queue.add(
      `${eventType}:${ep.id}`,
      {
        endpointId: ep.id,
        eventId,
        eventType,
        payload,
        timestamp,
      },
      {
        jobId: `${eventId}:${ep.id}`, // Idempotent per event + endpoint
      }
    );
    if (job.id) jobIds.push(job.id);
  }

  return jobIds;
}

export async function testWebhookEndpoint(endpointId: string) {
  const endpoint = await prisma.webhookEndpoint.findUniqueOrThrow({
    where: { id: endpointId },
  });

  const testPayload = {
    test: true,
    message: "Ping event from BOXMEOUT webhook subsystem",
    timestamp: new Date().toISOString(),
  };

  const eventId = `test_${uuidv4()}`;
  return executeWebhookDelivery(
    endpoint.url,
    endpoint.secret,
    eventId,
    "test.ping",
    testPayload
  );
}
