# Node.js Advanced Patterns

Advanced patterns for dependency injection, database integration, authentication, caching, and API response formatting.

## Dependency Injection

### DI Container

```typescript
// di-container.ts
import { Pool } from "pg";
import { UserRepository } from "./repositories/user.repository";
import { UserService } from "./services/user.service";
import { UserController } from "./controllers/user.controller";
import { AuthService } from "./services/auth.service";

class Container {
  private instances = new Map<string, any>();

  register<T>(key: string, factory: () => T): void {
    this.instances.set(key, factory);
  }

  resolve<T>(key: string): T {
    const factory = this.instances.get(key);
    if (!factory) {
      throw new Error(`No factory registered for ${key}`);
    }
    return factory();
  }

  singleton<T>(key: string, factory: () => T): void {
    let instance: T;
    this.instances.set(key, () => {
      if (!instance) {
        instance = factory();
      }
      return instance;
    });
  }
}

export const container = new Container();

// Register dependencies
container.singleton(
  "db",
  () =>
    new Pool({
      host: process.env.DB_HOST,
      port: parseInt(process.env.DB_PORT || "5432"),
      database: process.env.DB_NAME,
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      max: 20,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 2000,
    }),
);

container.singleton(
  "userRepository",
  () => new UserRepository(container.resolve("db")),
);

container.singleton(
  "userService",
  () => new UserService(container.resolve("userRepository")),
);

container.register(
  "userController",
  () => new UserController(container.resolve("userService")),
);

container.singleton(
  "authService",
  () =>
    new AuthService(
      container.resolve("userRepository"),
      container.resolve("db"),
    ),
);
```

## Database Patterns

### PostgreSQL with Connection Pool

```typescript
// config/database.ts
import { Pool, PoolConfig } from "pg";

const poolConfig: PoolConfig = {
  host: process.env.DB_HOST,
  port: parseInt(process.env.DB_PORT || "5432"),
  database: process.env.DB_NAME,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
};

export const pool = new Pool(poolConfig);

// Test connection
pool.on("connect", () => {
  console.log("Database connected");
});

pool.on("error", (err) => {
  console.error("Unexpected database error", err);
  process.exit(-1);
});

// Graceful shutdown
export const closeDatabase = async () => {
  await pool.end();
  console.log("Database connection closed");
};
```

### MongoDB with Mongoose

```typescript
// config/mongoose.ts
import mongoose from "mongoose";

const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGODB_URI!, {
      maxPoolSize: 10,
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
    });

    console.log("MongoDB connected");
  } catch (error) {
    console.error("MongoDB connection error:", error);
    process.exit(1);
  }
};

mongoose.connection.on("disconnected", () => {
  console.log("MongoDB disconnected");
});

mongoose.connection.on("error", (err) => {
  console.error("MongoDB error:", err);
});

export { connectDB };

// Model example
import { Schema, model, Document } from "mongoose";

interface IUser extends Document {
  name: string;
  email: string;
  password: string;
  createdAt: Date;
  updatedAt: Date;
}

const userSchema = new Schema<IUser>(
  {
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
  },
  {
    timestamps: true,
  },
);

// Indexes
userSchema.index({ email: 1 });

export const User = model<IUser>("User", userSchema);
```

### Transaction Pattern

```typescript
// services/order.service.ts
import { Pool } from "pg";

export class OrderService {
  constructor(private db: Pool) {}

  async createOrder(userId: string, items: any[]) {
    const client = await this.db.connect();

    try {
      await client.query("BEGIN");

      // Create order
      const orderResult = await client.query(
        "INSERT INTO orders (user_id, total) VALUES ($1, $2) RETURNING id",
        [userId, calculateTotal(items)],
      );
      const orderId = orderResult.rows[0].id;

      // Create order items
      for (const item of items) {
        await client.query(
          "INSERT INTO order_items (order_id, product_id, quantity, price) VALUES ($1, $2, $3, $4)",
          [orderId, item.productId, item.quantity, item.price],
        );

        // Update inventory
        await client.query(
          "UPDATE products SET stock = stock - $1 WHERE id = $2",
          [item.quantity, item.productId],
        );
      }

      await client.query("COMMIT");
      return orderId;
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }
}
```

## Authentication & Authorization

### JWT Authentication

```typescript
// services/auth.service.ts
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { Pool, PoolClient } from "pg";
import { UserRepository } from "../repositories/user.repository";
import { UnauthorizedError } from "../utils/errors";

const ACCESS_TOKEN_TTL = "15m";
const REFRESH_TOKEN_TTL_MS = 7 * 24 * 60 * 60 * 1000;

// Refresh tokens are opaque random values, not JWTs. Only a SHA-256 hash is
// stored, so a database leak does not hand out usable tokens, and every
// token can be revoked server-side.
//
// CREATE TABLE refresh_tokens (
//   token_hash  text PRIMARY KEY,
//   user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
//   family_id   uuid NOT NULL,
//   expires_at  timestamptz NOT NULL,
//   revoked_at  timestamptz
// );
// CREATE INDEX refresh_tokens_family_idx ON refresh_tokens (family_id);
// CREATE INDEX refresh_tokens_user_idx ON refresh_tokens (user_id);
const hashToken = (token: string): string =>
  createHash("sha256").update(token).digest("hex");

export class AuthService {
  constructor(
    private userRepository: UserRepository,
    private db: Pool,
  ) {}

  async login(email: string, password: string) {
    const user = await this.userRepository.findByEmail(email);

    if (!user) {
      throw new UnauthorizedError("Invalid credentials");
    }

    const isValid = await bcrypt.compare(password, user.password);

    if (!isValid) {
      throw new UnauthorizedError("Invalid credentials");
    }

    // If the account uses MFA, verify the second factor here. No token is
    // issued on a password alone.

    const token = this.generateToken({
      userId: user.id,
      email: user.email,
    });

    // Each login starts a new token family.
    const refreshToken = await this.issueRefreshToken(
      this.db,
      user.id,
      randomUUID(),
    );

    return {
      token,
      refreshToken,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
      },
    };
  }

  // Rotation: a refresh token works exactly once. Using it revokes it and
  // issues a replacement in the same family. If a revoked token shows up
  // again, someone is replaying it, so the whole family is revoked.
  async refreshToken(presented: string) {
    const client = await this.db.connect();
    let reuseDetected = false;
    let result: { token: string; refreshToken: string } | null = null;

    try {
      await client.query("BEGIN");

      // FOR UPDATE makes two requests with the same token run one at a time.
      const { rows } = await client.query(
        `SELECT user_id, family_id, expires_at, revoked_at
           FROM refresh_tokens
          WHERE token_hash = $1
            FOR UPDATE`,
        [hashToken(presented)],
      );
      const stored = rows[0];

      if (!stored || stored.expires_at <= new Date()) {
        throw new UnauthorizedError("Invalid refresh token");
      }

      if (stored.revoked_at) {
        await client.query(
          `UPDATE refresh_tokens
              SET revoked_at = now()
            WHERE family_id = $1 AND revoked_at IS NULL`,
          [stored.family_id],
        );
        reuseDetected = true;
      } else {
        const user = await this.userRepository.findById(stored.user_id);
        if (!user) {
          throw new UnauthorizedError("Invalid refresh token");
        }

        await client.query(
          "UPDATE refresh_tokens SET revoked_at = now() WHERE token_hash = $1",
          [hashToken(presented)],
        );

        result = {
          token: this.generateToken({ userId: user.id, email: user.email }),
          refreshToken: await this.issueRefreshToken(
            client,
            user.id,
            stored.family_id,
          ),
        };
      }

      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }

    if (reuseDetected || !result) {
      throw new UnauthorizedError("Invalid refresh token");
    }
    return result;
  }

  // Logout ends this session: every token in the family is revoked.
  async logout(presented: string): Promise<void> {
    await this.db.query(
      `UPDATE refresh_tokens
          SET revoked_at = now()
        WHERE revoked_at IS NULL
          AND family_id = (
            SELECT family_id FROM refresh_tokens WHERE token_hash = $1
          )`,
      [hashToken(presented)],
    );
  }

  // Call on password change, MFA enable or disable, and account lockout.
  // Ends every session the user has on every device.
  async revokeAllSessions(userId: string): Promise<void> {
    await this.db.query(
      `UPDATE refresh_tokens
          SET revoked_at = now()
        WHERE user_id = $1 AND revoked_at IS NULL`,
      [userId],
    );
  }

  private async issueRefreshToken(
    db: Pool | PoolClient,
    userId: string,
    familyId: string,
  ): Promise<string> {
    const token = randomBytes(32).toString("base64url");
    await db.query(
      `INSERT INTO refresh_tokens (token_hash, user_id, family_id, expires_at)
       VALUES ($1, $2, $3, $4)`,
      [
        hashToken(token),
        userId,
        familyId,
        new Date(Date.now() + REFRESH_TOKEN_TTL_MS),
      ],
    );
    return token;
  }

  // An access token already issued stays valid until it expires, so keep
  // this TTL short. If a revoked session must stop within seconds, add a
  // server-side check on each request (a session or token-version lookup).
  private generateToken(payload: { userId: string; email: string }): string {
    return jwt.sign(payload, process.env.JWT_SECRET!, {
      algorithm: "HS256",
      expiresIn: ACCESS_TOKEN_TTL,
    });
  }
}
```

## Caching Strategies

```typescript
// utils/cache.ts
import Redis from "ioredis";

const redis = new Redis({
  host: process.env.REDIS_HOST,
  port: parseInt(process.env.REDIS_PORT || "6379"),
  retryStrategy: (times) => {
    const delay = Math.min(times * 50, 2000);
    return delay;
  },
});

export class CacheService {
  async get<T>(key: string): Promise<T | null> {
    const data = await redis.get(key);
    return data ? JSON.parse(data) : null;
  }

  async set(key: string, value: any, ttl?: number): Promise<void> {
    const serialized = JSON.stringify(value);
    if (ttl) {
      await redis.setex(key, ttl, serialized);
    } else {
      await redis.set(key, serialized);
    }
  }

  async delete(key: string): Promise<void> {
    await redis.del(key);
  }

  async invalidatePattern(pattern: string): Promise<void> {
    const keys = await redis.keys(pattern);
    if (keys.length > 0) {
      await redis.del(...keys);
    }
  }
}

// Cache decorator
export function Cacheable(ttl: number = 300) {
  return function (
    target: any,
    propertyKey: string,
    descriptor: PropertyDescriptor,
  ) {
    const originalMethod = descriptor.value;

    descriptor.value = async function (...args: any[]) {
      const cache = new CacheService();
      const cacheKey = `${propertyKey}:${JSON.stringify(args)}`;

      const cached = await cache.get(cacheKey);
      if (cached) {
        return cached;
      }

      const result = await originalMethod.apply(this, args);
      await cache.set(cacheKey, result, ttl);

      return result;
    };

    return descriptor;
  };
}
```

## API Response Format

```typescript
// utils/response.ts
import { Response } from "express";

export class ApiResponse {
  static success<T>(
    res: Response,
    data: T,
    message?: string,
    statusCode = 200,
  ) {
    return res.status(statusCode).json({
      status: "success",
      message,
      data,
    });
  }

  static error(res: Response, message: string, statusCode = 500, errors?: any) {
    return res.status(statusCode).json({
      status: "error",
      message,
      ...(errors && { errors }),
    });
  }

  static paginated<T>(
    res: Response,
    data: T[],
    page: number,
    limit: number,
    total: number,
  ) {
    return res.json({
      status: "success",
      data,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit),
      },
    });
  }
}
```
