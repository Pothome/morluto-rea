import { Buffer } from "node:buffer";
import {
  SNAPSHOT_HASH_LENGTH,
  SNAPSHOT_HASH_OFFSET,
  SNAPSHOT_HASH_PATTERN,
} from "./FlutterPayloadScan.js";

/** Bounds-checked little-endian reader over one loaded buffer. */
class BoundedReader {
  constructor(private readonly bytes: Buffer) {}

  u8(offset: number): number | null {
    return offset < this.bytes.length ? this.bytes.readUInt8(offset) : null;
  }

  u16(offset: number): number | null {
    return offset + 2 <= this.bytes.length
      ? this.bytes.readUInt16LE(offset)
      : null;
  }

  u32(offset: number): number | null {
    return offset + 4 <= this.bytes.length
      ? this.bytes.readUInt32LE(offset)
      : null;
  }

  u64(offset: number): number | null {
    const low = this.u32(offset);
    const high = this.u32(offset + 4);
    if (low === null || high === null || high > 0x001fffff) return null;
    return high * 0x1_0000_0000 + low;
  }

  cString(offset: number, max: number): string | null {
    if (offset < 0 || offset >= this.bytes.length) return null;
    // Bound the terminator scan to the max name length plus one, so a
    // malformed symbol table cannot scan the entire image per entry.
    const limit = Math.min(this.bytes.length, offset + max + 1);
    const end = this.bytes.subarray(offset, limit).indexOf(0);
    if (end === -1 || end > max) return null;
    return this.bytes.subarray(offset, offset + end).toString("latin1");
  }
}

export interface ElfSymbol {
  readonly name: string;
  /** File offset mapped from the virtual address through PT_LOAD. */
  readonly offset: number;
  readonly size: number;
}

export interface ElfParseFailure {
  readonly reason: string;
}

const SHT_DYNSYM = 11;
const PT_LOAD = 1;
const PT_DYNAMIC = 2;
/** Position-independent executable images carry PT_DYNAMIC. */
const ET_DYN = 3;
const DT_NULL = 0;
const DT_STRTAB = 5;
const DT_SYMTAB = 6;
const DT_STRSZ = 10;
const DT_SYMENT = 11;

/** ELF32 needs 52 bytes, ELF64 needs 64; retain at most this prefix. */
export const ELF_HEADER_MAX_BYTES = 64;

/**
 * Decode the supported ELF header and validate its table extents against
 * the complete image size. The buffer may contain only the header prefix;
 * this does not validate table contents or symbol availability.
 */
export const readElfHeader = (
  bytes: Buffer,
  totalBytes: number = bytes.length,
) => {
  const reader = new BoundedReader(bytes);
  const magic = reader.u32(0);
  if (magic !== 0x464c457f) return { failure: { reason: "not an ELF image" } };
  const elfClass = reader.u8(4);
  if (elfClass !== 1 && elfClass !== 2)
    return { failure: { reason: `unsupported ELF class ${String(elfClass)}` } };
  const is64 = elfClass === 2;
  const headerBytes = is64 ? ELF_HEADER_MAX_BYTES : 52;
  if (
    bytes.length < headerBytes ||
    !Number.isSafeInteger(totalBytes) ||
    totalBytes < headerBytes
  )
    return { failure: { reason: "ELF header is truncated" } };
  if (reader.u8(5) !== 1)
    return { failure: { reason: "unsupported ELF byte order" } };
  if (reader.u8(6) !== 1 || reader.u32(0x14) !== 1)
    return { failure: { reason: "unsupported ELF version" } };
  if (reader.u16(is64 ? 0x34 : 0x28) !== headerBytes)
    return { failure: { reason: "unsupported ELF header size" } };
  const e_type = reader.u16(0x10);
  if (e_type !== 1 && e_type !== 2 && e_type !== ET_DYN)
    return { failure: { reason: "unsupported ELF type" } };
  const e_shoff = is64 ? reader.u64(0x28) : reader.u32(0x20);
  const e_shentsize = reader.u16(is64 ? 0x3a : 0x2e);
  const e_shnum = reader.u16(is64 ? 0x3c : 0x30);
  const e_phoff = is64 ? reader.u64(0x20) : reader.u32(0x1c);
  const e_phentsize = reader.u16(is64 ? 0x36 : 0x2a);
  const e_phnum = reader.u16(is64 ? 0x38 : 0x2c);
  const tableFits = (
    offset: number | null,
    width: number | null,
    count: number | null,
    minimumWidth: number,
  ): boolean =>
    offset !== null &&
    width !== null &&
    count !== null &&
    offset >= headerBytes &&
    offset <= totalBytes &&
    width >= minimumWidth &&
    count > 0 &&
    count <= Math.floor((totalBytes - offset) / width);
  const MIN_SHENT = is64 ? 64 : 40;
  // Section-stripped ET_DYN images keep their exported symbols reachable
  // through PT_DYNAMIC instead of section headers; every other shape still
  // needs a usable section header table.
  // A nonzero shoff with shnum=0 uses extended numbering, which this
  // parser does not support; it must not masquerade as a stripped image.
  const dynamicFallback = e_type === ET_DYN && e_shoff === 0 && e_shnum === 0;
  if (
    e_shoff === null ||
    e_shentsize === null ||
    e_shnum === null ||
    (!dynamicFallback && !tableFits(e_shoff, e_shentsize, e_shnum, MIN_SHENT))
  )
    return {
      failure: {
        reason: "ELF section header table is missing or out of bounds",
      },
    };
  const MIN_PHENT = is64 ? 56 : 32;
  if (
    e_phoff === null ||
    e_phentsize === null ||
    e_phnum === null ||
    e_phnum === 0xffff ||
    !tableFits(e_phoff, e_phentsize, e_phnum, MIN_PHENT)
  )
    return {
      failure: {
        reason: "ELF program header table is missing or out of bounds",
      },
    };

  return {
    header: {
      is64,
      dynamicFallback,
      e_shoff,
      e_shentsize,
      e_shnum,
      e_phoff,
      e_phentsize,
      e_phnum,
    },
  };
};

/** Resolve an exported snapshot symbol using the validated ELF tables. */
export const readElfSymbol = (
  bytes: Buffer,
  symbolName: string,
): { symbol: ElfSymbol } | { failure: ElfParseFailure } => {
  const parsed = readElfHeader(bytes);
  if (parsed.failure !== undefined) return { failure: parsed.failure };
  const {
    is64,
    dynamicFallback,
    e_shoff,
    e_shentsize,
    e_shnum,
    e_phoff,
    e_phentsize,
    e_phnum,
  } = parsed.header;
  const reader = new BoundedReader(bytes);
  const entrySize = is64 ? 24 : 16;

  const segments: {
    readonly vaddr: number;
    readonly offset: number;
    readonly filesz: number;
  }[] = [];
  let dynamicSegment: { offset: number; filesz: number } | null = null;
  for (let index = 0; index < e_phnum; index += 1) {
    const base = e_phoff + index * e_phentsize;
    const type = reader.u32(base);
    if (type === PT_DYNAMIC) {
      const offset = is64 ? reader.u64(base + 0x08) : reader.u32(base + 4);
      const filesz = is64 ? reader.u64(base + 0x20) : reader.u32(base + 0x10);
      if (offset === null || filesz === null)
        return {
          failure: {
            reason: `PT_DYNAMIC segment ${String(index)} is truncated`,
          },
        };
      dynamicSegment = { offset, filesz };
      continue;
    }
    if (type !== PT_LOAD) continue;
    const vaddr = is64 ? reader.u64(base + 0x10) : reader.u32(base + 8);
    const offset = is64 ? reader.u64(base + 0x08) : reader.u32(base + 4);
    const filesz = is64 ? reader.u64(base + 0x20) : reader.u32(base + 0x10);
    if (vaddr === null || offset === null || filesz === null)
      return {
        failure: { reason: `PT_LOAD segment ${String(index)} is truncated` },
      };
    segments.push({ vaddr, offset, filesz });
  }
  if (segments.length === 0)
    return { failure: { reason: "ELF image has no PT_LOAD segments" } };
  const toOffset = (vaddr: number, size: number): number | null => {
    let best: {
      vaddr: number;
      offset: number;
      filesz: number;
    } | null = null;
    for (const segment of segments)
      if (
        segment.vaddr <= vaddr &&
        (best === null || segment.vaddr > best.vaddr)
      )
        best = segment;
    if (best === null) return null;
    const delta = vaddr - best.vaddr;
    // The full symbol must sit inside the file-backed portion of the
    // segment; addresses in a gap or BSS are not snapshot bytes.
    if (delta + size > best.filesz) return null;
    return best.offset + delta;
  };

  /** Read one dynsym entry; null when its fields do not parse. */
  const readEntry = (
    base: number,
  ): { nameOffset: number; stValue: number; stSize: number } | null => {
    const nameOffset = reader.u32(base);
    const stValue = is64 ? reader.u64(base + 8) : reader.u32(base + 4);
    const stSize = is64 ? reader.u64(base + 16) : reader.u32(base + 8);
    if (nameOffset === null || stValue === null || stSize === null) return null;
    return { nameOffset, stValue, stSize };
  };

  /** Map one located symbol to its file offset, refusing unmappable values. */
  const resolve = (
    name: string,
    stValue: number,
    stSize: number,
  ): { symbol: ElfSymbol } | { failure: ElfParseFailure } => {
    const fileOffset = toOffset(stValue, stSize);
    if (fileOffset === null)
      return {
        failure: { reason: `symbol ${symbolName} has no loadable address` },
      };
    if (fileOffset + stSize > bytes.length)
      return {
        failure: { reason: `symbol ${symbolName} extends past the image` },
      };
    return { symbol: { name, offset: fileOffset, size: stSize } };
  };

  // Primary path: locate the dynamic symbol table through section headers.
  for (let index = 0; index < e_shnum; index += 1) {
    const header = e_shoff + index * e_shentsize;
    const type = reader.u32(is64 ? header + 4 : header + 4);
    if (type !== SHT_DYNSYM) continue;
    const offset = is64 ? reader.u64(header + 0x18) : reader.u32(header + 0x10);
    const size = is64 ? reader.u64(header + 0x20) : reader.u32(header + 0x14);
    const link = reader.u32(is64 ? header + 0x28 : header + 0x18);
    if (offset === null || size === null)
      return { failure: { reason: "dynamic symbol table is truncated" } };
    if (offset + size > bytes.length || size % entrySize !== 0)
      return { failure: { reason: "dynamic symbol table is malformed" } };
    if (link === null || link >= e_shnum)
      return {
        failure: {
          reason: "dynamic symbol table string section link is invalid",
        },
      };
    const stringHeader = e_shoff + link * e_shentsize;
    const stringOffset = is64
      ? reader.u64(stringHeader + 0x18)
      : reader.u32(stringHeader + 0x10);
    const stringSize = is64
      ? reader.u64(stringHeader + 0x20)
      : reader.u32(stringHeader + 0x14);
    if (
      stringOffset === null ||
      stringSize === null ||
      stringOffset + stringSize > bytes.length
    )
      return {
        failure: { reason: "dynamic symbol strings are out of bounds" },
      };
    for (let entry = 0; entry < size / entrySize; entry += 1) {
      const parsed = readEntry(offset + entry * entrySize);
      if (parsed === null) continue;
      // Bound the name lookup to the linked string table: a st_name
      // outside the table or a terminator beyond it reads unrelated
      // payload bytes, not a symbol name.
      if (parsed.nameOffset >= stringSize) continue;
      const name = reader.cString(
        stringOffset + parsed.nameOffset,
        Math.min(256, stringSize - parsed.nameOffset),
      );
      if (name !== symbolName) continue;
      return resolve(name, parsed.stValue, parsed.stSize);
    }
  }

  // Fallback path: section-stripped ET_DYN images name their dynamic symbol
  // table through PT_DYNAMIC tag-value pairs instead of section headers.
  // The segment records no symbol count, so the walk stops where the string
  // table begins (the standard layout places it after the symbols), at the
  // first entry that no longer parses, or at the end of the image.
  if (dynamicFallback && dynamicSegment !== null) {
    const dynamicEntrySize = is64 ? 16 : 8;
    let symbolTableVaddr: number | null = null;
    let stringTableVaddr: number | null = null;
    let stringTableBytes: number | null = null;
    let declaredEntrySize: number | null = null;
    const dynamicEnd = Math.min(
      bytes.length,
      dynamicSegment.offset + dynamicSegment.filesz,
    );
    for (
      let base = dynamicSegment.offset;
      base + dynamicEntrySize <= dynamicEnd;
      base += dynamicEntrySize
    ) {
      const tag = is64 ? reader.u64(base) : reader.u32(base);
      const value = is64 ? reader.u64(base + 8) : reader.u32(base + 4);
      if (tag === null || value === null || tag === DT_NULL) break;
      if (tag === DT_SYMTAB) symbolTableVaddr = value;
      else if (tag === DT_STRTAB) stringTableVaddr = value;
      else if (tag === DT_STRSZ) stringTableBytes = value;
      else if (tag === DT_SYMENT) declaredEntrySize = value;
    }
    if (
      symbolTableVaddr !== null &&
      stringTableVaddr !== null &&
      (declaredEntrySize === null || declaredEntrySize === entrySize)
    ) {
      const tableOffset = toOffset(symbolTableVaddr, 0);
      const stringOffset = toOffset(stringTableVaddr, 0);
      if (tableOffset !== null && stringOffset !== null) {
        const walkEnd =
          stringOffset > tableOffset ? stringOffset : bytes.length;
        for (
          let base = tableOffset;
          base + entrySize <= walkEnd;
          base += entrySize
        ) {
          const parsed = readEntry(base);
          if (parsed === null) break;
          if (
            stringTableBytes !== null &&
            parsed.nameOffset >= stringTableBytes
          )
            break;
          const name = reader.cString(
            stringOffset + parsed.nameOffset,
            stringTableBytes === null
              ? 256
              : Math.min(256, stringTableBytes - parsed.nameOffset),
          );
          if (name === null) break;
          if (name !== symbolName) continue;
          return resolve(name, parsed.stValue, parsed.stSize);
        }
      }
    }
  }
  return {
    failure: {
      reason: `symbol ${symbolName} is not in the dynamic symbol table`,
    },
  };
};

/** Read one Dart snapshot section header from its file offset. */
export const readSnapshotHeader = (
  bytes: Buffer,
  offset: number,
): {
  magicValid: boolean;
  kind: number | null;
  headerLength: number | null;
  hash: string | null;
  complete: boolean;
} => {
  const reader = new BoundedReader(bytes);
  // The Dart magic bytes f5 f5 dc dc read little-endian. Kind and length
  // fields are only meaningful in data-section headers; sections without
  // the magic (instructions carry a different layout) report nulls.
  const magic = reader.u32(offset);
  if (magic !== 0xdcdcf5f5)
    return {
      magicValid: false,
      kind: null,
      headerLength: null,
      hash: null,
      complete: false,
    };
  const headerLength = reader.u64(offset + 4);
  const kind = reader.u64(offset + 12);
  const candidate = bytes
    .subarray(
      offset + SNAPSHOT_HASH_OFFSET,
      offset + SNAPSHOT_HASH_OFFSET + SNAPSHOT_HASH_LENGTH,
    )
    .toString("latin1");
  const hash = SNAPSHOT_HASH_PATTERN.test(candidate) ? candidate : null;
  // Dart's stored length excludes the four magic bytes and includes the
  // 20-byte fixed header and the version hash. Aligned data may follow it
  // inside the exported symbol, but the serialized snapshot must fit.
  const complete =
    headerLength !== null &&
    headerLength >= SNAPSHOT_HASH_OFFSET + SNAPSHOT_HASH_LENGTH - 4 &&
    headerLength <= bytes.length - offset - 4 &&
    kind !== null &&
    hash !== null;
  return { magicValid: true, kind, headerLength, hash, complete };
};

export const buildElf64Image = (
  symbols: ReadonlyArray<{ name: string; value: number; size: number }>,
): Buffer => {
  const ELF_HEADER = 64;
  const PHENT = 56;
  const PHNUM = 1;
  const SHENT = 64;
  const phoff = ELF_HEADER;
  const shoffAligned = phoff + PHENT * PHNUM;
  // Place payload data after the three section headers so nothing overlaps.
  const dynsymOff = shoffAligned + 3 * SHENT + 16;
  const dynstrOff = dynsymOff + symbols.length * 24;
  const image = Buffer.alloc(dynstrOff + 256);
  // ELF header
  image.writeUInt32LE(0x464c457f, 0);
  image[4] = 2; // ELFCLASS64
  image[5] = 1; // little-endian
  image[6] = 1; // ELF identification version
  image.writeUInt16LE(ET_DYN, 0x10);
  image.writeUInt16LE(0x003e, 0x12); // e_machine x86_64
  image.writeUInt32LE(1, 0x14); // e_version
  image.writeUInt16LE(ELF_HEADER, 0x34);
  image.writeBigUInt64LE(BigInt(phoff), 0x20);
  image.writeBigUInt64LE(BigInt(shoffAligned), 0x28);
  image.writeUInt16LE(PHENT, 0x36);
  image.writeUInt16LE(PHNUM, 0x38);
  image.writeUInt16LE(SHENT, 0x3a);
  image.writeUInt16LE(2, 0x3c); // e_shnum: null + dynsym
  // Program header: one PT_LOAD mapping identity
  const ph = phoff;
  image.writeUInt32LE(1, ph); // PT_LOAD
  image.writeBigUInt64LE(BigInt(0), ph + 8); // offset
  image.writeBigUInt64LE(BigInt(0), ph + 0x10); // vaddr
  image.writeBigUInt64LE(BigInt(0x10000), ph + 0x20); // p_filesz generously covers fixture symbols
  // Section headers
  const sh = shoffAligned;
  // null section stays zero
  const dyn = sh + SHENT;
  image.writeUInt32LE(11, dyn + 4); // SHT_DYNSYM
  image.writeBigUInt64LE(BigInt(dynsymOff), dyn + 0x18);
  image.writeBigUInt64LE(BigInt(symbols.length * 24), dyn + 0x20);
  image.writeUInt32LE(2, dyn + 0x28); // sh_link -> strtab section index
  // dynstr section header
  const str = dyn + SHENT;
  image.writeUInt32LE(3, str + 4); // SHT_STRTAB
  image.writeBigUInt64LE(BigInt(dynstrOff), str + 0x18);
  image.writeBigUInt64LE(BigInt(256), str + 0x20);
  image.writeUInt16LE(3, 0x3c); // e_shnum includes strtab
  // dynstr: leading NUL then names
  let strCursor = dynstrOff + 1;
  const nameOffsets = symbols.map((symbol) => {
    image.write(symbol.name, strCursor, "latin1");
    const at = strCursor - dynstrOff;
    strCursor += symbol.name.length + 1;
    return at;
  });
  // dynsym entries
  symbols.forEach((symbol, index) => {
    const base = dynsymOff + index * 24;
    image.writeUInt32LE(nameOffsets[index]!, base);
    image.writeBigUInt64LE(BigInt(symbol.value), base + 8);
    image.writeBigUInt64LE(BigInt(symbol.size), base + 16);
    image[base + 4] = 0x10; // GLOBAL FUNC
  });
  return image;
};

/**
 * Build a section-stripped ELF64 image (e_shnum 0, ET_DYN) whose exported
 * symbols are reachable only through the PT_DYNAMIC tag-value pairs, the
 * way release toolchains ship `libapp.so`.
 */
export const buildStrippedElf64Image = (
  symbols: ReadonlyArray<{ name: string; value: number; size: number }>,
): Buffer => {
  const ELF_HEADER = 64;
  const PHENT = 56;
  const PHNUM = 2;
  const dynamicEntry = 16;
  // DT_SYMTAB, DT_STRTAB, DT_STRSZ, DT_SYMENT, then a DT_NULL terminator.
  const DYNAMIC_ENTRIES = 5;
  const phoff = ELF_HEADER;
  const dynamicOff = phoff + PHENT * PHNUM;
  const dynsymOff = dynamicOff + DYNAMIC_ENTRIES * dynamicEntry;
  const dynstrOff = dynsymOff + symbols.length * 24;
  const strtabBytes = 256;
  const image = Buffer.alloc(dynstrOff + strtabBytes);
  // ELF header
  image.writeUInt32LE(0x464c457f, 0);
  image[4] = 2; // ELFCLASS64
  image[5] = 1; // little-endian
  image[6] = 1;
  image.writeUInt16LE(ET_DYN, 0x10);
  image.writeUInt16LE(0x003e, 0x12); // e_machine x86_64
  image.writeUInt32LE(1, 0x14);
  image.writeUInt16LE(ELF_HEADER, 0x34);
  image.writeBigUInt64LE(BigInt(phoff), 0x20);
  image.writeUInt16LE(PHENT, 0x36);
  image.writeUInt16LE(PHNUM, 0x38);
  // e_shoff, e_shentsize, and e_shnum stay zero: no section headers exist.
  // PT_LOAD identity-maps the file so symbol vaddrs resolve to offsets.
  const load = phoff;
  image.writeUInt32LE(PT_LOAD, load);
  image.writeBigUInt64LE(BigInt(0), load + 8);
  image.writeBigUInt64LE(BigInt(0), load + 0x10);
  image.writeBigUInt64LE(BigInt(0x10000), load + 0x20); // p_filesz covers fixture symbols
  // PT_DYNAMIC locates the symbol table for stripped images.
  const dyn = phoff + PHENT;
  image.writeUInt32LE(PT_DYNAMIC, dyn);
  image.writeBigUInt64LE(BigInt(dynamicOff), dyn + 8); // p_offset
  image.writeBigUInt64LE(BigInt(dynamicOff), dyn + 0x10); // p_vaddr
  image.writeBigUInt64LE(BigInt(DYNAMIC_ENTRIES * dynamicEntry), dyn + 0x20);
  const pairs: ReadonlyArray<readonly [number, number]> = [
    [DT_SYMTAB, dynsymOff],
    [DT_STRTAB, dynstrOff],
    [DT_STRSZ, strtabBytes],
    [DT_SYMENT, 24],
  ];
  pairs.forEach(([tag, value], index) => {
    const base = dynamicOff + index * dynamicEntry;
    image.writeBigUInt64LE(BigInt(tag), base);
    image.writeBigUInt64LE(BigInt(value), base + 8);
  });
  // The final entry stays zero: DT_NULL terminates the walk.
  // dynstr: leading NUL then names
  let strCursor = dynstrOff + 1;
  const nameOffsets = symbols.map((symbol) => {
    image.write(symbol.name, strCursor, "latin1");
    const at = strCursor - dynstrOff;
    strCursor += symbol.name.length + 1;
    return at;
  });
  symbols.forEach((symbol, index) => {
    const base = dynsymOff + index * 24;
    image.writeUInt32LE(nameOffsets[index]!, base);
    image.writeBigUInt64LE(BigInt(symbol.value), base + 8);
    image.writeBigUInt64LE(BigInt(symbol.size), base + 16);
  });
  return image;
};

/** A minimal Dart snapshot data section carrying a 32-hex hash. */
export const snapshotSection = (hash: string): Buffer =>
  Buffer.concat([
    Buffer.from([
      0xf5, 0xf5, 0xdc, 0xdc, 48, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0,
    ]),
    Buffer.from(hash, "latin1"),
  ]);
