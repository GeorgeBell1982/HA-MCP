import { constants } from "node:fs";
import { open } from "node:fs/promises";

export interface Phase2DurabilityPort {
  readonly privateMode: (mode: bigint) => boolean;
  readonly syncDirectory: (path: string) => Promise<void>;
}

export const strictPhase2Durability: Phase2DurabilityPort = Object.freeze({
  privateMode: (mode: bigint) => (Number(mode) & 0o077) === 0,
  syncDirectory: async (path: string) => {
    const handle = await open(path, constants.O_RDONLY);
    try {
      await handle.sync();
    } finally {
      await handle.close();
    }
  },
});
