/**
 * Minimal stand-in for iconv-lite, used only in the Cloudflare Workers build.
 *
 * body-parser depends on iconv-lite to convert request bodies whose charset is not UTF-8.
 * The real package fails to bundle for Workers: esbuild's CommonJS interop turns its internal
 * `require("./streams")` into a value that is not callable, and the Worker dies during startup
 * validation with "require_streams(...) is not a function".
 *
 * Shimming it is safe here rather than merely convenient. This API accepts JSON only, and JSON
 * is defined as UTF-8; Stripe sends UTF-8; the Zod schemas reject anything that does not parse.
 * So the only encodings that can legitimately reach body-parser are ones Buffer handles
 * natively. Anything else is refused loudly instead of being silently mangled, which is what a
 * charset converter that quietly guessed would do.
 */

import { StringDecoder } from 'node:string_decoder';

const SUPPORTED = new Set([
  'utf8',
  'utf-8',
  'ascii',
  'us-ascii',
  'latin1',
  'binary',
  'iso-8859-1',
  'ucs2',
  'ucs-2',
  'utf16le',
  'utf-16le',
  'base64',
  'hex',
]);

/** Map an incoming charset label onto the Node buffer encoding that implements it. */
function bufferEncoding(encoding: string): BufferEncoding {
  const key = String(encoding || '').toLowerCase().trim();
  switch (key) {
    case 'utf8':
    case 'utf-8':
      return 'utf8';
    case 'ascii':
    case 'us-ascii':
      return 'ascii';
    case 'latin1':
    case 'binary':
    case 'iso-8859-1':
      return 'latin1';
    case 'ucs2':
    case 'ucs-2':
    case 'utf16le':
    case 'utf-16le':
      return 'utf16le';
    case 'base64':
      return 'base64';
    case 'hex':
      return 'hex';
    default:
      throw new Error(`Unsupported charset "${encoding}"`);
  }
}

export function encodingExists(encoding: string): boolean {
  return SUPPORTED.has(String(encoding || '').toLowerCase().trim());
}

export function decode(buffer: Buffer, encoding: string): string {
  return Buffer.from(buffer).toString(bufferEncoding(encoding));
}

export function encode(content: string, encoding: string): Buffer {
  return Buffer.from(content, bufferEncoding(encoding));
}

/**
 * Streaming decoder, in the shape raw-body expects: repeated write() calls followed by end().
 *
 * StringDecoder rather than a plain toString because raw-body feeds arbitrary chunks and a
 * multi-byte character can straddle a chunk boundary. Decoding each chunk independently would
 * corrupt any non-ASCII character that happened to land on the split, which for this API means
 * a customer with an accent in their name silently failing checkout.
 */
export function getDecoder(encoding: string): { write(buffer: Buffer): string; end(): string } {
  const decoder = new StringDecoder(bufferEncoding(encoding));
  return {
    write: (buffer: Buffer) => decoder.write(buffer),
    end: () => decoder.end(),
  };
}

export function getEncoder(encoding: string): { write(value: string): Buffer; end(): Buffer } {
  const target = bufferEncoding(encoding);
  return {
    write: (value: string) => Buffer.from(value, target),
    end: () => Buffer.alloc(0),
  };
}

export function getCodec(encoding: string): { encoder: BufferEncoding } {
  return { encoder: bufferEncoding(encoding) };
}

export default { encodingExists, decode, encode, getDecoder, getEncoder, getCodec };
