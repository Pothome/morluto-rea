import { describe, expect, it } from "vitest";

import {
  buildElf64Image,
  buildStrippedElf64Image,
  readElfSymbol,
  readSnapshotHeader,
  snapshotSection,
} from "./DartElf.js";
import { REFERENCE_HASH } from "./FlutterTestFixtures.js";

/**
 * Build a synthetic ELF64 little-endian image with one PT_LOAD segment
 * and a dynamic symbol table naming the Dart snapshot sections. This keeps
 * the golden tests self-contained instead of reading the author's disk.
 */
const GALLERY_HASH = REFERENCE_HASH;

const imageWithSections = (): Buffer => {
  const elf = buildElf64Image([
    { name: "_kDartVmSnapshotData", value: 0x400, size: 52 },
    { name: "_kDartIsolateSnapshotData", value: 0x800, size: 52 },
  ]);
  const section = snapshotSection(GALLERY_HASH);
  return Buffer.concat([
    elf,
    Buffer.alloc(0x400 - elf.length),
    section,
    Buffer.alloc(0x800 - 0x400 - section.length),
    section,
  ]);
};

/** The same layout without section headers: symbols live in PT_DYNAMIC. */
const strippedImageWithSections = (): Buffer => {
  const elf = buildStrippedElf64Image([
    { name: "_kDartVmSnapshotData", value: 0x400, size: 52 },
    { name: "_kDartIsolateSnapshotData", value: 0x800, size: 52 },
  ]);
  const section = snapshotSection(GALLERY_HASH);
  return Buffer.concat([
    elf,
    Buffer.alloc(0x400 - elf.length),
    section,
    Buffer.alloc(0x800 - 0x400 - section.length),
    section,
  ]);
};

describe("readElfSymbol", () => {
  it("locates snapshot symbols in a synthetic ELF64 image", () => {
    const image = imageWithSections();
    const isolateData = readElfSymbol(image, "_kDartIsolateSnapshotData");
    if ("failure" in isolateData) throw new Error(isolateData.failure.reason);
    expect(isolateData.symbol.offset).toBe(0x800);
    expect(isolateData.symbol.size).toBe(52);
    const header = readSnapshotHeader(image, isolateData.symbol.offset);
    expect(header.magicValid).toBe(true);
    expect(header.kind).toBe(3);
  });

  it("refuses a non-ELF image instead of guessing", () => {
    const result = readElfSymbol(Buffer.from("not an elf at all"), "x");
    expect("failure" in result && result.failure.reason).toBe(
      "not an ELF image",
    );
  });

  it("refuses an unknown symbol", () => {
    const result = readElfSymbol(buildElf64Image([]), "_kDartAbsent");
    expect("failure" in result).toBe(true);
  });

  it("locates snapshot symbols in a section-stripped ET_DYN image", () => {
    const image = strippedImageWithSections();
    const isolateData = readElfSymbol(image, "_kDartIsolateSnapshotData");
    if ("failure" in isolateData) throw new Error(isolateData.failure.reason);
    expect(isolateData.symbol.offset).toBe(0x800);
    expect(isolateData.symbol.size).toBe(52);
    const header = readSnapshotHeader(image, isolateData.symbol.offset);
    expect(header.magicValid).toBe(true);
    expect(header.kind).toBe(3);
  });

  it("refuses a stripped image whose PT_DYNAMIC carries no symbols", () => {
    // Drop the PT_DYNAMIC program header by leaving only PT_LOAD.
    const image = buildStrippedElf64Image([
      { name: "_kDartVmSnapshotData", value: 0x400, size: 52 },
    ]);
    image.writeUInt16LE(1, 0x38); // e_phnum
    const result = readElfSymbol(image, "_kDartVmSnapshotData");
    expect("failure" in result && result.failure.reason).toBe(
      "symbol _kDartVmSnapshotData is not in the dynamic symbol table",
    );
  });

  it("keeps refusing a stripped image that is not ET_DYN", () => {
    const image = buildStrippedElf64Image([]);
    image.writeUInt16LE(1, 0x10); // ET_REL: the dynamic fallback must not apply
    const result = readElfSymbol(image, "_kDartVmSnapshotData");
    expect("failure" in result && result.failure.reason).toBe(
      "ELF section header table is missing or out of bounds",
    );
  });
});

describe("readSnapshotHeader", () => {
  it("reads a synthesized data header", () => {
    const header = readSnapshotHeader(snapshotSection(GALLERY_HASH), 0);
    expect(header.magicValid).toBe(true);
    expect(header.kind).toBe(3);
  });

  it("reports nulls for sections without the data magic", () => {
    const header = readSnapshotHeader(Buffer.from([0, 0, 0, 0, 0, 0, 0, 0]), 0);
    expect(header).toEqual({
      magicValid: false,
      kind: null,
      headerLength: null,
      hash: null,
      complete: false,
    });
  });
});
