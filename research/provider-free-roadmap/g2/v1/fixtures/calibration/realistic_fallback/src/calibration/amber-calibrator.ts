export class AmberCalibrator {
  constructor(private readonly base: number) {}

  window(trim: number): string {
    return `AMBER-${this.base + trim}`;
  }
}
