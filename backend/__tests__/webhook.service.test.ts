import dns from "dns";
import {
  isPrivateOrReservedIPv4,
  isPrivateOrReservedIPv6,
  isBlockedIp,
  validateWebhookUrl,
  generateWebhookSignature,
  verifyWebhookSignature,
  executeWebhookDelivery,
} from "../src/services/webhook.service";

describe("Webhook Service - B-145 Outbound Webhooks", () => {
  describe("1. HMAC-SHA256 Signature generation & verification", () => {
    const secret = "whsec_test_secret_for_unit_tests_123456";
    const timestamp = 1700000000000;
    const body = JSON.stringify({ event: "market.created", marketId: "MKT_001" });

    it("generates deterministic HMAC-SHA256 signature matching payload", () => {
      const sig1 = generateWebhookSignature(secret, timestamp, body);
      const sig2 = generateWebhookSignature(secret, timestamp, body);

      expect(sig1).toBeDefined();
      expect(sig1).toHaveLength(64); // SHA-256 hex digest length
      expect(sig1).toEqual(sig2);
    });

    it("verifies valid signature successfully", () => {
      const sig = generateWebhookSignature(secret, timestamp, body);
      const isValid = verifyWebhookSignature(secret, timestamp, body, sig);
      expect(isValid).toBe(true);
    });

    it("rejects tampered body or timestamp", () => {
      const sig = generateWebhookSignature(secret, timestamp, body);
      const tamperedBody = JSON.stringify({ event: "market.created", marketId: "MKT_HACKED" });

      expect(verifyWebhookSignature(secret, timestamp, tamperedBody, sig)).toBe(false);
      expect(verifyWebhookSignature(secret, timestamp + 1, body, sig)).toBe(false);
      expect(verifyWebhookSignature("different_secret", timestamp, body, sig)).toBe(false);
    });

    it("rejects invalid signature string safely without throwing", () => {
      expect(verifyWebhookSignature(secret, timestamp, body, "invalid_non_hex")).toBe(false);
      expect(verifyWebhookSignature(secret, timestamp, body, "")).toBe(false);
    });
  });

  describe("2. SSRF Protection - IP and Range Validation", () => {
    it("blocks IPv4 loopback addresses (127.0.0.0/8)", () => {
      expect(isPrivateOrReservedIPv4("127.0.0.1")).toBe(true);
      expect(isPrivateOrReservedIPv4("127.1.2.3")).toBe(true);
      expect(isBlockedIp("127.0.0.1")).toBe(true);
    });

    it("blocks RFC 1918 private IPv4 ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)", () => {
      expect(isPrivateOrReservedIPv4("10.0.0.1")).toBe(true);
      expect(isPrivateOrReservedIPv4("10.254.1.1")).toBe(true);
      expect(isPrivateOrReservedIPv4("172.16.0.1")).toBe(true);
      expect(isPrivateOrReservedIPv4("172.31.255.254")).toBe(true);
      expect(isPrivateOrReservedIPv4("192.168.1.1")).toBe(true);
      expect(isPrivateOrReservedIPv4("192.168.100.200")).toBe(true);
    });

    it("blocks link-local and AWS/cloud metadata address (169.254.169.254)", () => {
      expect(isPrivateOrReservedIPv4("169.254.169.254")).toBe(true);
      expect(isPrivateOrReservedIPv4("169.254.1.1")).toBe(true);
      expect(isBlockedIp("169.254.169.254")).toBe(true);
    });

    it("blocks carrier-grade NAT, multicast, reserved and broadcast IPv4", () => {
      expect(isPrivateOrReservedIPv4("100.64.0.1")).toBe(true); // CGNAT
      expect(isPrivateOrReservedIPv4("0.0.0.0")).toBe(true); // Default route
      expect(isPrivateOrReservedIPv4("224.0.0.1")).toBe(true); // Multicast
      expect(isPrivateOrReservedIPv4("240.0.0.1")).toBe(true); // Reserved
    });

    it("allows standard public IPv4 addresses", () => {
      expect(isPrivateOrReservedIPv4("8.8.8.8")).toBe(false);
      expect(isPrivateOrReservedIPv4("1.1.1.1")).toBe(false);
      expect(isPrivateOrReservedIPv4("93.184.216.34")).toBe(false); // example.com
    });

    it("blocks IPv6 loopback (::1) and unspecified (::)", () => {
      expect(isPrivateOrReservedIPv6("::1")).toBe(true);
      expect(isPrivateOrReservedIPv6("::")).toBe(true);
      expect(isBlockedIp("::1")).toBe(true);
    });

    it("blocks IPv6 Unique Local Addresses (fc00::/7)", () => {
      expect(isPrivateOrReservedIPv6("fc00::1")).toBe(true);
      expect(isPrivateOrReservedIPv6("fd12:3456:789a::1")).toBe(true);
    });

    it("blocks IPv6 Link-Local Addresses (fe80::/10)", () => {
      expect(isPrivateOrReservedIPv6("fe80::1")).toBe(true);
      expect(isPrivateOrReservedIPv6("fe90::abcd")).toBe(true);
    });

    it("blocks IPv4-mapped IPv6 pointing to private addresses", () => {
      expect(isPrivateOrReservedIPv6("::ffff:127.0.0.1")).toBe(true);
      expect(isPrivateOrReservedIPv6("::ffff:10.0.0.1")).toBe(true);
      expect(isPrivateOrReservedIPv6("::ffff:169.254.169.254")).toBe(true);
      expect(isPrivateOrReservedIPv6("::ffff:192.168.1.1")).toBe(true);
    });
  });

  describe("3. SSRF Protection - URL & DNS Resolution Validation", () => {
    it("rejects non-https schemes (http, ftp, file, javascript)", async () => {
      await expect(validateWebhookUrl("http://example.com/webhook")).rejects.toThrow(
        /SSRF validation failed: webhook URLs must strictly use https: protocol/
      );
      await expect(validateWebhookUrl("ftp://example.com/webhook")).rejects.toThrow(
        /SSRF validation failed: webhook URLs must strictly use https: protocol/
      );
      await expect(validateWebhookUrl("file:///etc/passwd")).rejects.toThrow(
        /SSRF validation failed: webhook URLs must strictly use https: protocol/
      );
    });

    it("rejects localhost and internal domain names", async () => {
      await expect(validateWebhookUrl("https://localhost/webhook")).rejects.toThrow(
        /SSRF validation failed: blocked host/
      );
      await expect(validateWebhookUrl("https://service.internal/webhook")).rejects.toThrow(
        /SSRF validation failed: blocked host/
      );
      await expect(validateWebhookUrl("https://cluster.local/webhook")).rejects.toThrow(
        /SSRF validation failed: blocked host/
      );
    });

    it("rejects IP literals in private ranges directly", async () => {
      await expect(validateWebhookUrl("https://127.0.0.1/webhook")).rejects.toThrow(
        /SSRF validation failed/
      );
      await expect(validateWebhookUrl("https://10.0.0.1/webhook")).rejects.toThrow(
        /SSRF validation failed/
      );
      await expect(validateWebhookUrl("https://169.254.169.254/webhook")).rejects.toThrow(
        /SSRF validation failed/
      );
      await expect(validateWebhookUrl("https://192.168.1.100/webhook")).rejects.toThrow(
        /SSRF validation failed/
      );
    });

    it("detects and rejects DNS rebinding to private IPs", async () => {
      // Mock dns.promises.lookup to simulate a domain resolving to an internal IP
      const lookupSpy = (jest.spyOn(dns.promises, "lookup") as jest.SpyInstance<any>).mockResolvedValueOnce([
        { address: "192.168.1.50", family: 4 },
      ]);

      await expect(validateWebhookUrl("https://malicious-rebinding.example.com/webhook")).rejects.toThrow(
        /resolved to blocked address/
      );

      lookupSpy.mockRestore();
    });

    it("detects and rejects DNS resolving to AWS metadata service (169.254.169.254)", async () => {
      const lookupSpy = (jest.spyOn(dns.promises, "lookup") as jest.SpyInstance<any>).mockResolvedValueOnce([
        { address: "169.254.169.254", family: 4 },
      ]);

      await expect(validateWebhookUrl("https://attacker-metadata.example.com/hook")).rejects.toThrow(
        /resolved to blocked address/
      );

      lookupSpy.mockRestore();
    });

    it("passes for valid public https destinations", async () => {
      const lookupSpy = (jest.spyOn(dns.promises, "lookup") as jest.SpyInstance<any>).mockResolvedValueOnce([
        { address: "93.184.216.34", family: 4 },
      ]);

      const parsed = await validateWebhookUrl("https://api.partner.com/events");
      expect(parsed.protocol).toBe("https:");
      expect(parsed.hostname).toBe("api.partner.com");

      lookupSpy.mockRestore();
    });
  });

  describe("4. Request Delivery Guard (redirects, timeout, signature headers)", () => {
    it("fails delivery immediately if URL is SSRF-blocked", async () => {
      await expect(
        executeWebhookDelivery(
          "http://127.0.0.1/webhook",
          "secret123",
          "evt_1",
          "market.resolved",
          { id: "1" }
        )
      ).rejects.toThrow(/SSRF validation failed/);
    });

    it("blocks redirects by strictly configuring redirect: error", async () => {
      // Mock dns lookup to pass SSRF
      const lookupSpy = (jest.spyOn(dns.promises, "lookup") as jest.SpyInstance<any>).mockResolvedValue([
        { address: "93.184.216.34", family: 4 },
      ]);

      // Mock fetch with a redirect response (or redirect error)
      const fetchSpy = jest.spyOn(globalThis, "fetch").mockImplementationOnce(async (url, init) => {
        expect(init?.redirect).toBe("error");
        throw new TypeError("Failed to fetch: redirect prohibited");
      });

      await expect(
        executeWebhookDelivery(
          "https://redirector.example.com/hook",
          "secret123",
          "evt_1",
          "market.resolved",
          { id: "1" }
        )
      ).rejects.toThrow(/redirect prohibited/);

      fetchSpy.mockRestore();
      lookupSpy.mockRestore();
    });

    it("includes proper HMAC signature and delivery metadata headers on dispatch", async () => {
      const lookupSpy = (jest.spyOn(dns.promises, "lookup") as jest.SpyInstance<any>).mockResolvedValue([
        { address: "93.184.216.34", family: 4 },
      ]);

      let capturedHeaders: Record<string, string> = {};
      let capturedBody = "";

      const fetchSpy = jest.spyOn(globalThis, "fetch").mockImplementationOnce(async (url, init) => {
        capturedHeaders = init?.headers as Record<string, string>;
        capturedBody = init?.body as string;
        return {
          ok: true,
          status: 200,
          text: async () => JSON.stringify({ received: true }),
        } as Response;
      });

      const secret = "whsec_super_secret_for_mock_123456";
      const timestamp = 1700000050000;
      const res = await executeWebhookDelivery(
        "https://webhook.client.com/receive",
        secret,
        "evt_test_99",
        "market.created",
        { marketId: "MKT_777", title: "Heavyweight Championship" },
        timestamp
      );

      expect(res.statusCode).toBe(200);
      expect(capturedHeaders["Content-Type"]).toBe("application/json");
      expect(capturedHeaders["X-Boxmeout-Event"]).toBe("market.created");
      expect(capturedHeaders["X-Boxmeout-Delivery"]).toBe("evt_test_99");
      expect(capturedHeaders["X-Boxmeout-Timestamp"]).toBe(String(timestamp));

      // Signature header verification
      const sigHeader = capturedHeaders["X-Boxmeout-Signature"];
      expect(sigHeader).toBeDefined();
      expect(sigHeader).toMatch(/^t=\d+,v1=[0-9a-f]{64}$/);

      const parsedSig = sigHeader.split("v1=")[1];
      expect(verifyWebhookSignature(secret, timestamp, capturedBody, parsedSig)).toBe(true);

      fetchSpy.mockRestore();
      lookupSpy.mockRestore();
    });
  });
});
