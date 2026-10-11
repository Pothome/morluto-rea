import type { GhidraLanguageOverride } from "../config/ghidraLanguageOverride.js";
import type { BinaryTarget } from "../domain/binaryTargetTypes.js";
import type { JsonValue } from "../domain/jsonValue.js";

/**
 * Recordless legacy ELF32 MIPS admission: the header declares no ABI field and
 * carries no ABI flags record, so o32 is an analysis assumption derived from
 * ELF32/ET_EXEC structure, never a declared fact. Ghidra's header
 * auto-selection picks a 64-bit language for exactly these files, so the lane
 * pins the 32-bit language instead.
 */
export const isLegacyMipsAdmission = (target: BinaryTarget): boolean => {
  if (
    target.kind !== "executable" ||
    target.architecture !== "mips" ||
    target.format !== "elf" ||
    target.mips === undefined
  )
    return false;
  const { flags, abiFlags, limitations } = target.mips;
  const arch = flags & 0xf0000000;
  return (
    (arch === 0x50000000 || arch === 0x70000000) &&
    (flags & 0x0000f000) === 0 &&
    (flags & 0x20) === 0 &&
    // Undefined means the record was not inspected; only an inspected
    // absence establishes the recordless legacy admission. An inspection
    // that could not examine every declaration source stays unknown.
    abiFlags === null &&
    (limitations === undefined || limitations.length === 0)
  );
};

/** Keep family recognition separate from the deliberately bounded Ghidra lane. */
export const ghidraMipsUnsupportedReason = (
  target: BinaryTarget,
): string | null => {
  if (target.kind !== "executable" || target.architecture !== "mips")
    return null;
  const metadata = target.mips;
  if (target.format !== "elf" || metadata === undefined)
    return "MIPS analysis requires ELF header metadata; a family name alone does not select an ISA or ABI.";
  if (metadata.elfClass !== 32)
    return "This Ghidra MIPS lane supports ELF32 only; MIPS64 and n64 remain unsupported.";
  if (metadata.type !== 2)
    return "This Ghidra MIPS lane supports ET_EXEC only; relocatable objects, shared images and PSP PRX need separate load verification.";
  if ((metadata.flags & 0x0f000000) !== 0)
    return "MIPS16, microMIPS and other ASE encodings are outside this standard-instruction MIPS lane.";
  if ((metadata.flags & 0x00ff0000) !== 0)
    return "Machine-specific MIPS variants, including PSP Allegrex, need a separately supported processor profile.";
  const arch = metadata.flags & 0xf0000000;
  if (arch !== 0x70000000 && arch !== 0x50000000)
    return "This Ghidra MIPS lane requires EF_MIPS_ARCH_32R2 or a recordless legacy EF_MIPS_ARCH_32 header; other ISA revisions need separate verification.";
  const recordlessShape =
    (metadata.flags & 0x0000f000) === 0 &&
    (metadata.flags & 0x20) === 0 &&
    metadata.abiFlags === null;
  if (recordlessShape) {
    if ((metadata.flags & 0x00000200) !== 0)
      return "EF_MIPS_FP64 requires separate verification of 64-bit floating-point register semantics in this Ghidra lane.";
    if ((metadata.flags & 0x00000400) !== 0)
      return "EF_MIPS_NAN2008 requires separate verification of NaN encoding semantics in this Ghidra lane.";
    if (isLegacyMipsAdmission(target)) return null;
    // The inspection could not examine every ABI declaration source, so the
    // recordless admission is not established for this header.
    return [
      "This recordless legacy admission requires a complete ABI-record inspection; ABI declarations in unavailable headers remain unknown.",
      ...(metadata.limitations ?? []),
    ].join(" ");
  }
  if (
    (metadata.flags & 0x0000f000) !== 0x00001000 ||
    (metadata.flags & 0x20) !== 0
  )
    return "This Ghidra MIPS lane requires an explicit o32 ABI or a recordless legacy header with an unspecified ABI; n32, EABI and mixed declarations remain unsupported.";
  if (arch !== 0x70000000)
    return "This Ghidra MIPS lane requires EF_MIPS_ARCH_32R2 for headers that declare an ABI; EF_MIPS_ARCH_32 headers are admitted only through the recordless legacy admission.";
  if ((metadata.flags & 0x00000200) !== 0)
    return "EF_MIPS_FP64 requires separate verification of 64-bit floating-point register semantics in this Ghidra lane.";
  if ((metadata.flags & 0x00000400) !== 0)
    return "EF_MIPS_NAN2008 requires separate verification of NaN encoding semantics in this Ghidra lane.";
  const abi = metadata.abiFlags;
  if (abi === undefined || abi === null)
    return [
      "This Ghidra MIPS lane requires an inspected ABI flags record; header flags alone do not establish the floating-point ABI.",
      ...(metadata.limitations ?? []),
    ].join(" ");
  if (abi.version !== 0)
    return "This Ghidra MIPS lane requires ABI flags version 0; newer record semantics are unsupported.";
  if (abi.isaLevel !== 32 || abi.isaRevision !== 2)
    return "MIPS ABI flags must agree with the declared MIPS32r2 ISA.";
  if (abi.gprSize !== 1 || abi.cpr1Size !== 1 || abi.cpr2Size !== 0)
    return "This Ghidra MIPS lane requires 32-bit GPR/CPR1 and no CPR2; other register modes need separate verification.";
  if (abi.fpAbi !== 1 && abi.fpAbi !== 5)
    return "This Ghidra MIPS lane admits double-precision or FPXX ABI declarations only; soft-float, FP64 and unspecified modes need separate verification.";
  if (abi.isaExtension !== 0 || abi.ases !== 0)
    return "MIPS ABI flags declare an ISA extension or ASE outside this standard-instruction lane.";
  if ((abi.flags1 & ~1) !== 0 || abi.flags2 !== 0)
    return "MIPS ABI flags contain unsupported general flags.";
  return null;
};

/** Commit source ELF interpretation without confusing target ISA with host CPU. */
export const ghidraMipsProfileParameters = (
  target: BinaryTarget,
  languageOverride?: GhidraLanguageOverride,
): Readonly<Record<string, JsonValue>> => {
  if (
    target.kind !== "executable" ||
    target.architecture !== "mips" ||
    target.mips === undefined
  )
    return {};
  const abi = target.mips.abiFlags;
  // A deliberate caller-selected language wins over the legacy pin; the pin
  // exists because header auto-selection misselects a 64-bit language.
  const legacy = isLegacyMipsAdmission(target);
  const pinnedLanguage =
    legacy && languageOverride === undefined
      ? {
          language_id: `MIPS:${
            target.mips.byteOrder === "little" ? "LE" : "BE"
          }:32:default`,
          compiler_spec_id: "default",
          language_selection: "provider-pinned-v1",
        }
      : {};
  return {
    mips_elf: {
      elf_class: target.mips.elfClass,
      byte_order: target.mips.byteOrder,
      type: target.mips.type,
      flags: target.mips.flags,
      ...(target.mips.limitations === undefined
        ? {}
        : { abi_flags_limitations: [...target.mips.limitations] }),
      abi_flags:
        abi === undefined || abi === null
          ? null
          : {
              version: abi.version,
              isa_level: abi.isaLevel,
              isa_revision: abi.isaRevision,
              gpr_size: abi.gprSize,
              cpr1_size: abi.cpr1Size,
              cpr2_size: abi.cpr2Size,
              fp_abi: abi.fpAbi,
              isa_extension: abi.isaExtension,
              ases: abi.ases,
              flags1: abi.flags1,
              flags2: abi.flags2,
            },
    },
    mips_support_lane: legacy
      ? "elf32-exec-arch32-legacy-pinned-v1"
      : "elf32-exec-o32-arch32r2-standard-v3",
    ...(legacy ? { mips_abi_basis: "inferred-o32-assumption-v1" } : {}),
    ...pinnedLanguage,
  };
};

/** Read the provider-pinned import language back from a resolved legacy profile. */
export const ghidraPinnedMipsLanguage = (
  parameters: Readonly<Record<string, unknown>>,
): GhidraLanguageOverride | undefined => {
  if (parameters.language_selection !== "provider-pinned-v1") return undefined;
  const languageId = parameters.language_id;
  const compilerSpecId = parameters.compiler_spec_id;
  if (typeof languageId !== "string" || typeof compilerSpecId !== "string")
    return undefined;
  return compilerSpecId === "language-default"
    ? { languageId }
    : { languageId, compilerSpecId };
};
