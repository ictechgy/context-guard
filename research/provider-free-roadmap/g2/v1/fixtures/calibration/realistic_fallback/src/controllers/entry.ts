import { AmberCalibrator } from "../calibration/amber-calibrator";
import { recordProbe } from "../telemetry/probe";

export function amberWindow(): string {
  recordProbe("bounded-read");
  return new AmberCalibrator(240).window(6);
}
