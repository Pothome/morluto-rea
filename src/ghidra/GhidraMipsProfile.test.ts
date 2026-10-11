import { describe, expect, it } from "vitest";
import { parseConfig } from "../config/parseConfig.js";
import type {
  BinaryTarget,
  MipsElfMetadata,
} from "../domain/binaryTargetTypes.js";
import { silentLogger } from "../logger.js";
import { HopperProvider } from "../hopper/HopperProvider.js";
import { hopperLoaderArgsForTarget } from "../hopper/HopperAnalysisProfile.js";
import { IdaProvider } from "../ida/IdaProvider.js";
import { GhidraProvider } from "./GhidraProvider.js";
import {
  ghidraMipsProfileParameters,
  ghidraPinnedMipsLanguage,
} from "./GhidraMipsProfile.js";
import type { GhidraInstallationHost } from "./GhidraInstallation.js";

// Fake installation inspection tests admission/profile contracts, not Ghidra.
const host: GhidraInstallationHost = {
  platform: "linux",
  architecture: "x64",
  readText: () => "application.version=12.1.4\n",
  executable: () => true,
  probeJava: () => ({
    version: "21.0.11",
    major: 21,
    home: "/jdk-21",
    bits: 64,
    runtime: "jdk",
  }),
};
const parsed = parseConfig({ GHIDRA_INSTALL_DIR: "/ghidra" });
if (!parsed.ok) throw parsed.error;
const config = parsed.value;
const target = (change: Partial<MipsElfMetadata> = {}): BinaryTarget => ({
  path: "/fixture.elf",
  sha256: "a".repeat(64),
  kind: "executable",
  format: "elf",
  architecture: "mips",
  availableArchitectures: ["mips"],
  mips: {
    elfClass: 32,
    byteOrder: "little",
    type: 2,
    flags: 0x70001001,
    abiFlags: {
      version: 0,
      isaLevel: 32,
      isaRevision: 2,
      gprSize: 1,
      cpr1Size: 1,
      cpr2Size: 0,
      fpAbi: 5,
      isaExtension: 0,
      ases: 0,
      flags1: 0,
      flags2: 0,
    },
    ...change,
  },
});

describe("bounded Ghidra MIPS admission", () => {
  it("binds endian and flags without widening Windows P0", async () => {
    const ghidra = new GhidraProvider(config, silentLogger, {}, host);
    const little = target();
    const big = target({ byteOrder: "big" });
    expect(ghidra.inspectTargetSupport(little).status).toBe("supported");
    expect(ghidra.inspectTargetSupport(big).status).toBe("supported");
    const left = await ghidra.resolveAnalysisProfile(little);
    const right = await ghidra.resolveAnalysisProfile(big);
    if (!left.ok) throw left.error;
    if (!right.ok) throw right.error;
    expect(left.value.profile?.parameters.mips_elf).toEqual({
      elf_class: 32,
      byte_order: "little",
      type: 2,
      flags: 0x70001001,
      abi_flags: {
        version: 0,
        isa_level: 32,
        isa_revision: 2,
        gpr_size: 1,
        cpr1_size: 1,
        cpr2_size: 0,
        fp_abi: 5,
        isa_extension: 0,
        ases: 0,
        flags1: 0,
        flags2: 0,
      },
    });
    expect(left.value.profile?.digest).not.toBe(right.value.profile?.digest);
    const windows = new GhidraProvider(
      config,
      silentLogger,
      {},
      {
        ...host,
        platform: "win32",
      },
    );
    expect(windows.inspectTargetSupport(little).status).toBe("unsupported");
  });

  it.each([
    [{ elfClass: 64 }, "ELF32"],
    [{ type: 1 }, "ET_EXEC"],
    [{ type: 3 }, "ET_EXEC"],
    [{ type: 0xffa0 }, "ET_EXEC"],
    [{ flags: 0x10a23001 }, "separate MIPS ABI flags"],
    [{ flags: 0x70001021 }, "o32"],
    [{ flags: 0x70000001 }, "o32"],
    [{ flags: 0x70002001 }, "o32"],
    [{ flags: 0x70003001 }, "o32"],
    [{ flags: 0x70004001 }, "o32"],
    [{ flags: 0x72001001 }, "ASE"],
    [{ flags: 0x74001001 }, "ASE"],
    [{ flags: 0x70911001 }, "Machine-specific"],
    [{ flags: 0x60001001 }, "32R2"],
    [{ flags: 0x70001201 }, "EF_MIPS_FP64"],
    [{ flags: 0x70001401 }, "EF_MIPS_NAN2008"],
    [{ abiFlags: null }, "inspected ABI"],
  ] satisfies [Partial<MipsElfMetadata>, string][])(
    "refuses an unverified MIPS interpretation %j",
    async (change, reason) => {
      const ghidra = new GhidraProvider(config, silentLogger, {}, host);
      const value = target(change);
      expect(ghidra.inspectTargetSupport(value)).toMatchObject({
        status: "unsupported",
        reason: expect.stringContaining(reason),
      });
      const resolved = await ghidra.resolveAnalysisProfile(value);
      expect(resolved.ok).toBe(false);
    },
  );

  it("keeps MIPS out of unverified Hopper and IDA adapter lanes", () => {
    const hopper = new HopperProvider(config, silentLogger, {}, "linux");
    expect(hopper.inspectTargetSupport(target()).status).toBe("unsupported");
    expect(hopperLoaderArgsForTarget(target()).ok).toBe(false);
    const ida = new IdaProvider(config, {});
    expect(ida.inspectTargetSupport(target()).status).toBe("unsupported");
  });
});

describe("recordless legacy MIPS32 admission", () => {
  it.each([
    [{ flags: 0x50000001 }, "EF_MIPS_ARCH_32"],
    [{ flags: 0x70000001 }, "EF_MIPS_ARCH_32R2"],
  ] satisfies [Partial<MipsElfMetadata>, string][])(
    "admits a recordless legacy header (%s) with a pinned 32-bit language",
    async (change) => {
      const ghidra = new GhidraProvider(config, silentLogger, {}, host);
      const little = target({ ...change, abiFlags: null });
      const big = target({ ...change, abiFlags: null, byteOrder: "big" });
      expect(ghidra.inspectTargetSupport(little).status).toBe("supported");
      expect(ghidra.inspectTargetSupport(big).status).toBe("supported");
      const resolved = await ghidra.resolveAnalysisProfile(little);
      if (!resolved.ok) throw resolved.error;
      expect(resolved.value.profile?.parameters).toMatchObject({
        mips_support_lane: "elf32-exec-arch32-legacy-pinned-v1",
        mips_abi_basis: "inferred-o32-assumption-v1",
        language_id: "MIPS:LE:32:default",
        compiler_spec_id: "default",
        language_selection: "provider-pinned-v1",
      });
      const resolvedBig = await ghidra.resolveAnalysisProfile(big);
      if (!resolvedBig.ok) throw resolvedBig.error;
      expect(resolvedBig.value.profile?.parameters).toMatchObject({
        language_id: "MIPS:BE:32:default",
      });
    },
  );

  it("requires an inspected absence; a merely unobserved record stays refused", () => {
    const ghidra = new GhidraProvider(config, silentLogger, {}, host);
    const withRecord = target({ flags: 0x50000001 }) as BinaryTarget & {
      mips: MipsElfMetadata;
    };
    const { abiFlags: _record, ...unobservedMips } = withRecord.mips;
    void _record;
    expect(
      ghidra.inspectTargetSupport({
        ...withRecord,
        mips: unobservedMips,
      } as BinaryTarget),
    ).toMatchObject({
      status: "unsupported",
      reason: expect.stringContaining("recordless legacy header"),
    });
  });

  it.each([
    [{ flags: 0x50000021 }, "n32"],
    [
      { flags: 0x50001001 },
      "EF_MIPS_ARCH_32R2 for headers that declare an ABI",
    ],
    [{ flags: 0x50000201 }, "EF_MIPS_FP64"],
    [{ flags: 0x50000401 }, "EF_MIPS_NAN2008"],
    [{ flags: 0x60000001 }, "32R2"],
    [
      {
        flags: 0x50000001,
        limitations: [
          "MIPS section header table at file offset 96 extends beyond the captured file: examined 2 of 5 complete headers. ABI declarations in unavailable headers remain unknown.",
        ],
      },
      "complete ABI-record inspection",
    ],
  ] satisfies [Partial<MipsElfMetadata>, string][])(
    "keeps refusing unverified recordless variants %j",
    (change, reason) => {
      const ghidra = new GhidraProvider(config, silentLogger, {}, host);
      expect(
        ghidra.inspectTargetSupport(target({ ...change, abiFlags: null })),
      ).toMatchObject({
        status: "unsupported",
        reason: expect.stringContaining(reason),
      });
    },
  );

  it("a caller-selected language wins over the provider pin", () => {
    const parameters = ghidraMipsProfileParameters(
      target({ flags: 0x50000001, abiFlags: null }),
      { languageId: "MIPS:LE:32:default", compilerSpecId: "default" },
    );
    expect(parameters.language_selection).toBeUndefined();
    expect(parameters.language_id).toBeUndefined();
    expect(parameters).toMatchObject({
      mips_support_lane: "elf32-exec-arch32-legacy-pinned-v1",
    });
  });

  it("reads the pinned import language back only from pinned profiles", () => {
    const pinned = ghidraMipsProfileParameters(
      target({ flags: 0x50000001, abiFlags: null }),
    );
    expect(ghidraPinnedMipsLanguage(pinned)).toEqual({
      languageId: "MIPS:LE:32:default",
      compilerSpecId: "default",
    });
    const standard = ghidraMipsProfileParameters(target());
    expect(ghidraPinnedMipsLanguage(standard)).toBeUndefined();
  });
});
