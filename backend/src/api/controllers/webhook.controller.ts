import { Request, Response, NextFunction } from "express";
import { z } from "zod";
import * as webhookService from "../../services/webhook.service";
import { ok, fail } from "../response";

const CreateWebhookSchema = z.object({
  url: z.string().url("Must be a valid URL"),
  secret: z.string().min(16, "Secret must be at least 16 characters").optional(),
  eventTypes: z.array(z.string()).min(1, "At least one event type is required"),
  active: z.boolean().optional(),
});

const UpdateWebhookSchema = z.object({
  url: z.string().url("Must be a valid URL").optional(),
  secret: z.string().min(16, "Secret must be at least 16 characters").optional(),
  eventTypes: z.array(z.string()).min(1, "At least one event type is required").optional(),
  active: z.boolean().optional(),
});

export async function createWebhookHandler(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const parsed = CreateWebhookSchema.safeParse(req.body);
    if (!parsed.success) {
      fail(res, 400, "VALIDATION_ERROR", parsed.error.message);
      return;
    }

    const endpoint = await webhookService.createWebhookEndpoint(parsed.data);
    ok(res, endpoint, { status: 201 });
  } catch (err: unknown) {
    if (err instanceof Error && err.message.startsWith("SSRF validation failed")) {
      fail(res, 400, "SSRF_ERROR", err.message);
      return;
    }
    next(err);
  }
}

export async function listWebhooksHandler(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const active =
      req.query.active !== undefined
        ? req.query.active === "true" || req.query.active === "1"
        : undefined;

    const endpoints = await webhookService.listWebhookEndpoints({ active });
    ok(res, endpoints);
  } catch (err) {
    next(err);
  }
}

export async function getWebhookHandler(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const { id } = req.params;
    const endpoint = await webhookService.getWebhookEndpoint(id);
    if (!endpoint) {
      fail(res, 404, "NOT_FOUND", "Webhook endpoint not found");
      return;
    }
    ok(res, endpoint);
  } catch (err) {
    next(err);
  }
}

export async function updateWebhookHandler(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const { id } = req.params;
    const parsed = UpdateWebhookSchema.safeParse(req.body);
    if (!parsed.success) {
      fail(res, 400, "VALIDATION_ERROR", parsed.error.message);
      return;
    }

    const updated = await webhookService.updateWebhookEndpoint(id, parsed.data);
    ok(res, updated);
  } catch (err: unknown) {
    if (err instanceof Error && err.message.startsWith("SSRF validation failed")) {
      fail(res, 400, "SSRF_ERROR", err.message);
      return;
    }
    next(err);
  }
}

export async function deleteWebhookHandler(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const { id } = req.params;
    await webhookService.deleteWebhookEndpoint(id);
    ok(res, { deleted: true });
  } catch (err) {
    next(err);
  }
}

export async function testWebhookHandler(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const { id } = req.params;
    const result = await webhookService.testWebhookEndpoint(id);
    ok(res, result);
  } catch (err: unknown) {
    if (err instanceof Error && err.message.startsWith("SSRF validation failed")) {
      fail(res, 400, "SSRF_ERROR", err.message);
      return;
    }
    next(err);
  }
}
