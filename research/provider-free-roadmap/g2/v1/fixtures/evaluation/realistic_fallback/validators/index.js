export { releaseToken } from "../app/runner.js";

export function verifyIndigo(series, suffix) {
  if (series !== 800) throw new Error("invalid release series");
  return `INDIGO-${series + suffix}`;
}
