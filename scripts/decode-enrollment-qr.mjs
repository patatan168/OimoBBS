/** 製品と独立した検証専用デコーダーでPNGを読み取る。秘密は呼び出し元へだけ返す。 */
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
const require = createRequire(import.meta.url);
const jsQR = require(process.env.OIMO_QR_JSQR);
const { PNG } = require(process.env.OIMO_QR_PNGJS);
const image = PNG.sync.read(readFileSync(process.argv[2]));
const result = jsQR(new Uint8ClampedArray(image.data), image.width, image.height);
if (!result) throw new Error("QR decoding failed");
process.stdout.write(result.data);
