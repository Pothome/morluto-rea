import { Buffer } from "node:buffer";

import { buildElf64Image, snapshotSection } from "./DartElf.js";

export { buildElf64Image, snapshotSection };

/** The reference Gallery snapshot hash for synthetic fixtures. */
export const REFERENCE_HASH = "65817c30a78bb44c3dc3771876b6010a";

/** A synthetic AOT image with four symbols, two data sections, and a pool. */
export const aotFixtureImage = (hash: string = REFERENCE_HASH): Buffer => {
  const elf = buildElf64Image([
    { name: "_kDartVmSnapshotData", value: 0x1000, size: 52 },
    { name: "_kDartVmSnapshotInstructions", value: 0x1800, size: 16 },
    { name: "_kDartIsolateSnapshotData", value: 0x2000, size: 0x600 },
    { name: "_kDartIsolateSnapshotInstructions", value: 0x2600, size: 16 },
  ]);
  const pool = Buffer.concat([
    Buffer.from(
      "package:adaptive_breakpoints/src/adaptive_breakpoints.dart\x00",
    ),
    Buffer.from("package:animations/src/fade_scale_transition.dart\x00"),
    Buffer.from("dart:_http\x00dart:_http/crypto.dart\x00"),
    Buffer.from("AdaptiveBreakpoint\x00FadeScaleTransition\x00"),
  ]);
  const vmSection = snapshotSection(hash);
  const isolateSection = Buffer.concat([
    snapshotSection(hash),
    Buffer.from([0]),
    pool,
  ]);
  return Buffer.concat([
    elf,
    Buffer.alloc(0x1000 - elf.length),
    vmSection,
    Buffer.alloc(0x1800 - 0x1000 - vmSection.length),
    Buffer.alloc(16),
    Buffer.alloc(0x2000 - 0x1800 - 16),
    isolateSection,
    Buffer.alloc(0x600 - isolateSection.length),
    Buffer.alloc(16),
  ]);
};
