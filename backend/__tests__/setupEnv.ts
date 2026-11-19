// Default environment for every Jest worker. Values here are placeholders:
// tests that need real infrastructure must mock it, not connect to it.
process.env.NODE_ENV = process.env.NODE_ENV ?? "test";
process.env.DATABASE_URL =
  process.env.DATABASE_URL ?? "postgresql://boxmeout:boxmeout@localhost:5432/boxmeout_test";
process.env.REDIS_URL = process.env.REDIS_URL ?? "redis://localhost:6379";
process.env.STELLAR_NETWORK = process.env.STELLAR_NETWORK ?? "testnet";
process.env.STELLAR_RPC_URL = process.env.STELLAR_RPC_URL ?? "https://soroban-testnet.stellar.org";
process.env.STELLAR_HORIZON_URL = process.env.STELLAR_HORIZON_URL ?? "https://horizon-testnet.stellar.org";
process.env.MARKET_FACTORY_CONTRACT_ID = process.env.MARKET_FACTORY_CONTRACT_ID ?? "CA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ";
process.env.TREASURY_CONTRACT_ID = process.env.TREASURY_CONTRACT_ID ?? "CB6QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ";
process.env.ADMIN_SECRET_KEY = process.env.ADMIN_SECRET_KEY ?? "SA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ";
process.env.ADMIN_API_KEY = process.env.ADMIN_API_KEY ?? "test-admin-api-key";
process.env.ORACLE_API_KEY = process.env.ORACLE_API_KEY ?? "test-oracle-api-key";

