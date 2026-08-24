import jwt, { JwtPayload } from 'jsonwebtoken';

export interface ActivationClaims {
  licenseId: string;
  activationId: string;
  machineHash: string;
}

export interface IssuedToken {
  accessToken: string;
  tokenExpiresAt: string;
}

export interface TokenService {
  issue(claims: ActivationClaims): IssuedToken;
  verify(token: string): ActivationClaims;
}

export function createTokenService(secret: string, ttlSeconds: number): TokenService {
  return {
    issue: (claims) => {
      const nowSeconds = Math.floor(Date.now() / 1000);
      const expiresAtSeconds = nowSeconds + ttlSeconds;
      const accessToken = jwt.sign(
        {
          aid: claims.activationId,
          mh: claims.machineHash,
          typ: 'activation',
        },
        secret,
        {
          algorithm: 'HS256',
          audience: 'extguard-extension',
          issuer: 'extguard-api',
          subject: claims.licenseId,
          expiresIn: ttlSeconds,
        },
      );
      return {
        accessToken,
        tokenExpiresAt: new Date(expiresAtSeconds * 1000).toISOString(),
      };
    },
    verify: (token) => {
      const decoded = jwt.verify(token, secret, {
        algorithms: ['HS256'],
        audience: 'extguard-extension',
        issuer: 'extguard-api',
      }) as JwtPayload;
      if (
        decoded.typ !== 'activation'
        || typeof decoded.sub !== 'string'
        || typeof decoded.aid !== 'string'
        || typeof decoded.mh !== 'string'
        || !/^[a-f0-9]{64}$/.test(decoded.mh)
      ) {
        throw new Error('Invalid activation token claims');
      }
      return {
        licenseId: decoded.sub,
        activationId: decoded.aid,
        machineHash: decoded.mh,
      };
    },
  };
}
