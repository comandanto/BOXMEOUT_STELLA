import request from "supertest";
import express from "express";
import adminRoutes from "../src/api/routes/admin.routes";
import * as webhookService from "../src/services/webhook.service";

jest.mock("../src/services/webhook.service");
jest.mock("../src/api/controllers/market.controller", () => ({
  getPendingResolutionsHandler: jest.fn((_req, res) => res.json([])),
  resolveDisputeHandler: jest.fn((_req, res) => res.json({})),
}));
jest.mock("../src/api/controllers/marketResolution.controller", () => ({
  resolveMarketByIdHandler: jest.fn((_req, res) => res.json({})),
  resolveMarketHandler: jest.fn((_req, res) => res.json({})),
}));
jest.mock("../src/api/controllers/oracle.controller", () => ({
  getAllOraclesHandler: jest.fn((_req, res) => res.json([])),
  createOracleHandler: jest.fn((_req, res) => res.json({})),
  updateOracleHandler: jest.fn((_req, res) => res.json({})),
  deleteOracleHandler: jest.fn((_req, res) => res.json({})),
}));
jest.mock("../src/api/controllers/audit.controller", () => ({
  getAuditLogsHandler: jest.fn((_req, res) => res.json([])),
}));
jest.mock("../src/api/controllers/market-reconciliation.controller", () => ({
  reconcileMarketHandler: jest.fn((_req, res) => res.json({})),
}));
jest.mock("../src/api/middleware/audit-log.middleware", () => ({
  auditLogMiddleware: (_req: unknown, _res: unknown, next: () => void) => next(),
}));
jest.mock("../src/logger", () => ({
  logger: { info: jest.fn(), error: jest.fn(), warn: jest.fn(), debug: jest.fn() },
  httpLogger: (_req: unknown, _res: unknown, next: () => void) => next(),
}));
jest.mock("../src/db", () => ({
  db: {
    adminLog: { create: jest.fn().mockResolvedValue({}) },
    auditLog: { create: jest.fn().mockResolvedValue({}) },
  },
}));

const ADMIN_KEY = "test-admin-api-key";

function createTestApp() {
  const app = express();
  app.use(express.json());
  app.use("/api/admin", adminRoutes);
  return app;
}

describe("Admin Outbound Webhooks API Routes (B-145)", () => {
  const app = createTestApp();

  beforeEach(() => {
    process.env.ADMIN_API_KEY = ADMIN_KEY;
    jest.clearAllMocks();
  });

  describe("POST /api/admin/webhooks", () => {
    it("creates a webhook endpoint with valid payload", async () => {
      const mockCreated = {
        id: "wh_123",
        url: "https://example.com/webhook",
        secret: "whsec_0123456789abcdef0123456789abcdef",
        eventTypes: ["market.created", "market.resolved"],
        active: true,
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      (webhookService.createWebhookEndpoint as jest.Mock).mockResolvedValueOnce(mockCreated);

      const res = await request(app)
        .post("/api/admin/webhooks")
        .set("X-Admin-Key", ADMIN_KEY)
        .send({
          url: "https://example.com/webhook",
          eventTypes: ["market.created", "market.resolved"],
        });

      expect(res.status).toBe(201);
      expect(res.body.data.id).toBe("wh_123");
      expect(res.body.data.url).toBe("https://example.com/webhook");
    });

    it("rejects invalid or non-https URL via validation error", async () => {
      const res = await request(app)
        .post("/api/admin/webhooks")
        .set("X-Admin-Key", ADMIN_KEY)
        .send({
          url: "not-a-url",
          eventTypes: ["market.created"],
        });

      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe("VALIDATION_ERROR");
    });

    it("returns SSRF_ERROR when SSRF validation rejects internal target", async () => {
      (webhookService.createWebhookEndpoint as jest.Mock).mockRejectedValueOnce(
        new Error("SSRF validation failed: blocked host \"localhost\"")
      );

      const res = await request(app)
        .post("/api/admin/webhooks")
        .set("X-Admin-Key", ADMIN_KEY)
        .send({
          url: "https://localhost/webhook",
          eventTypes: ["market.created"],
        });

      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe("SSRF_ERROR");
      expect(res.body.error.message).toContain("SSRF validation failed");
    });
  });

  describe("GET /api/admin/webhooks", () => {
    it("returns list of registered webhook endpoints", async () => {
      const mockList = [
        {
          id: "wh_1",
          url: "https://partner1.com/hook",
          eventTypes: ["*"],
          active: true,
        },
        {
          id: "wh_2",
          url: "https://partner2.com/hook",
          eventTypes: ["market.resolved"],
          active: false,
        },
      ];

      (webhookService.listWebhookEndpoints as jest.Mock).mockResolvedValueOnce(mockList);

      const res = await request(app)
        .get("/api/admin/webhooks")
        .set("X-Admin-Key", ADMIN_KEY);

      expect(res.status).toBe(200);
      expect(res.body.data).toHaveLength(2);
    });
  });

  describe("GET /api/admin/webhooks/:id", () => {
    it("returns single endpoint details including delivery history", async () => {
      const mockEndpoint = {
        id: "wh_1",
        url: "https://partner.com/hook",
        eventTypes: ["*"],
        active: true,
        deliveries: [
          {
            id: "del_1",
            eventId: "evt_100",
            eventType: "market.created",
            statusCode: 200,
            deliveredAt: new Date(),
          },
        ],
      };

      (webhookService.getWebhookEndpoint as jest.Mock).mockResolvedValueOnce(mockEndpoint);

      const res = await request(app)
        .get("/api/admin/webhooks/wh_1")
        .set("X-Admin-Key", ADMIN_KEY);

      expect(res.status).toBe(200);
      expect(res.body.data.id).toBe("wh_1");
      expect(res.body.data.deliveries).toHaveLength(1);
    });

    it("returns 404 when endpoint is not found", async () => {
      (webhookService.getWebhookEndpoint as jest.Mock).mockResolvedValueOnce(null);

      const res = await request(app)
        .get("/api/admin/webhooks/wh_not_found")
        .set("X-Admin-Key", ADMIN_KEY);

      expect(res.status).toBe(404);
      expect(res.body.error.code).toBe("NOT_FOUND");
    });
  });

  describe("PATCH /api/admin/webhooks/:id", () => {
    it("updates webhook endpoint successfully", async () => {
      const mockUpdated = {
        id: "wh_1",
        url: "https://new-url.com/hook",
        active: false,
      };

      (webhookService.updateWebhookEndpoint as jest.Mock).mockResolvedValueOnce(mockUpdated);

      const res = await request(app)
        .patch("/api/admin/webhooks/wh_1")
        .set("X-Admin-Key", ADMIN_KEY)
        .send({
          url: "https://new-url.com/hook",
          active: false,
        });

      expect(res.status).toBe(200);
      expect(res.body.data.active).toBe(false);
    });
  });

  describe("DELETE /api/admin/webhooks/:id", () => {
    it("deletes webhook endpoint successfully", async () => {
      (webhookService.deleteWebhookEndpoint as jest.Mock).mockResolvedValueOnce({});

      const res = await request(app)
        .delete("/api/admin/webhooks/wh_1")
        .set("X-Admin-Key", ADMIN_KEY);

      expect(res.status).toBe(200);
      expect(res.body.data.deleted).toBe(true);
    });
  });

  describe("POST /api/admin/webhooks/:id/test", () => {
    it("triggers test ping and returns delivery result", async () => {
      (webhookService.testWebhookEndpoint as jest.Mock).mockResolvedValueOnce({
        statusCode: 200,
        responseBody: "{\"received\":true}",
      });

      const res = await request(app)
        .post("/api/admin/webhooks/wh_1/test")
        .set("X-Admin-Key", ADMIN_KEY);

      expect(res.status).toBe(200);
      expect(res.body.data.statusCode).toBe(200);
    });
  });
});
