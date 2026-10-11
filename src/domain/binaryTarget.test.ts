import { describe, expect, it } from "vitest";

import {
  parseExecutableHeader,
  WASM_BINARY_MODULE_REASON,
} from "./binaryTarget.js";
import { dosMz, elf, fat, pe, thinMach } from "./binaryTarget.fixture.js";

describe("executable header parsing", () => {
  it("recognizes a DOS MZ without interpreting load-module bytes as e_lfanew", () => {
    expect(parseExecutableHeader(dosMz(), "x64")).toEqual({
      ok: true,
      value: {
        format: "dos-mz",
        architecture: "x86",
        availableArchitectures: ["x86"],
      },
    });
  });
  it.each([
    [elf(1, 1, 62), "elf", "x86_64"],
    [elf(2, 2, 183), "elf", "arm64"],
    [thinMach(0xfeedfacf, 0x0100000c), "mach-o", "arm64"],
    [thinMach(0xcefaedfe, 0x01000007), "mach-o", "x86_64"],
    [pe(0x8664), "pe", "x86_64"],
    [pe(0xaa64), "pe", "arm64"],
  ] as const)("parses metadata for %s", (bytes, format, architecture) => {
    const result = parseExecutableHeader(bytes, "arm64");
    expect(result.ok && result.value).toMatchObject({ format, architecture });
  });

  it("distinguishes native PE applications, DLLs, and managed assemblies", () => {
    const application = parseExecutableHeader(pe(0x8664), "x64");
    const library = parseExecutableHeader(pe(0x8664, 64, 0x2002), "x64");
    const managed = parseExecutableHeader(pe(0x8664, 64, 0x0002, true), "x64");
    const nonExecutable = parseExecutableHeader(pe(0x8664, 64, 0), "x64");

    expect(application.ok && application.value).toMatchObject({
      executableRole: "application",
      managed: false,
    });
    expect(library.ok && library.value).toMatchObject({
      executableRole: "shared-library",
      managed: false,
    });
    expect(managed.ok && managed.value).toMatchObject({
      executableRole: "application",
      managed: true,
    });
    expect(nonExecutable.ok && nonExecutable.value).toMatchObject({
      executableRole: "non-executable",
      managed: false,
    });
  });

  it("selects the host architecture from a FAT table", () => {
    const bytes = fat([0x01000007, 0x0100000c]);
    const arm = parseExecutableHeader(bytes, "arm64");
    const intel = parseExecutableHeader(bytes, "x64");
    expect(arm.ok && arm.value).toMatchObject({
      architecture: "arm64",
      availableArchitectures: ["x86_64", "arm64"],
    });
    expect(intel.ok && intel.value).toMatchObject({
      architecture: "x86_64",
      availableArchitectures: ["x86_64", "arm64"],
    });
  });

  it("rejects FAT files without a host-compatible slice", () => {
    expect(parseExecutableHeader(fat([0x01000007]), "arm64")).toMatchObject({
      ok: false,
    });
  });

  it.each([
    Buffer.alloc(0),
    Buffer.from([0x7f, 0x45, 0x4c, 0x46]),
    fat([], 2),
    pe(0xffff),
  ])("rejects malformed, truncated, or unsupported metadata", (bytes) => {
    expect(parseExecutableHeader(bytes, "arm64").ok).toBe(false);
  });

  it("rejects malformed PE optional-header commitments", () => {
    const wrongMagic = pe(0x8664);
    wrongMagic.writeUInt16LE(0x10b, 64 + 24);
    const truncatedDirectories = pe(0x8664);
    truncatedDirectories.writeUInt16LE(112, 64 + 20);
    truncatedDirectories.writeUInt32LE(16, 64 + 24 + 108);

    expect(parseExecutableHeader(wrongMagic, "x64").ok).toBe(false);
    expect(parseExecutableHeader(truncatedDirectories, "x64").ok).toBe(false);
  });
});

describe("executable header completeness", () => {
  const reason = (bytes: Buffer, fileSize = bytes.length) => {
    const result = parseExecutableHeader(bytes, "arm64", fileSize);
    return result.ok ? null : result.error;
  };

  it.each([
    [
      thinMach(0xcffaedfe, 0x0100000c).subarray(0, 12),
      "a 64-bit header needs 32 bytes",
    ],
    [
      thinMach(0xcefaedfe, 0x01000007).subarray(0, 27),
      "a 32-bit header needs 28 bytes",
    ],
    [elf(1, 1, 62).subarray(0, 51), "an ELF32 header needs 52 bytes"],
    [elf(2, 1, 183).subarray(0, 63), "an ELF64 header needs 64 bytes"],
  ])(
    "rejects a header shorter than its fixed size (%#)",
    (bytes, constraint) => {
      expect(reason(bytes)).toContain(constraint);
    },
  );

  it("rejects Mach-O load commands that extend past the file", () => {
    const header = thinMach(0xcffaedfe, 0x0100000c);
    header.writeUInt32LE(100, 20);

    expect(reason(header)).toBe(
      "truncated Mach-O load commands: the header declares 100 bytes after its 32-byte header; the file has 32",
    );
    // The resolver probes a prefix; commitments are checked against the file.
    expect(reason(header, 132)).toBeNull();
  });

  it("rejects a FAT file whose host slice extends past the file", () => {
    const bytes = fat([0x01000007, 0x0100000c]);
    bytes.writeUInt32BE(4096, 8 + 20 + 8);
    bytes.writeUInt32BE(64, 8 + 20 + 12);

    expect(reason(bytes, 4100)).toBe(
      "truncated FAT slice: the arm64 slice ends at byte 4160; the file has 4100",
    );
    expect(reason(bytes, 4160)).toBeNull();
    // Only the slice REA would analyze must be present.
    expect(parseExecutableHeader(bytes, "x64", 4100).ok).toBe(true);
  });

  it("identifies a version-1 WebAssembly module preamble instead of an unknown format", () => {
    const wasm = Buffer.from([
      0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
    ]);
    expect(reason(wasm)).toBe(WASM_BINARY_MODULE_REASON);
    // An unknown module version is not claimed as a compatible v1 module.
    const future = Buffer.from([
      0x00, 0x61, 0x73, 0x6d, 0x0d, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00,
    ]);
    expect(reason(future)).toBe("unsupported binary format");
  });
});
