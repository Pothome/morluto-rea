import { createHash } from "node:crypto";
import { stat } from "node:fs/promises";

import { FlutterBuildAnalysisService } from "../dist/application/flutter/FlutterBuildAnalysisService.js";
import { createFlutterBuildAnalysisProvider } from "../dist/composition/flutter.js";

const options = parseArguments(process.argv.slice(2));
if (options.help) {
  process.stdout.write(
    "Usage: npm run verify:flutter [-- --apk PATH --plain-apk PATH]\n" +
      "Pure parsing; no engine or external tool is required. --apk selects a\n" +
      "real Flutter APK (a lib/<abi>/libapp.so carrier). --plain-apk optionally\n" +
      "selects a non-Flutter APK for the negative detection check.\n",
  );
  process.exit(0);
}

const provider = createFlutterBuildAnalysisProvider(process.env);
const service = new FlutterBuildAnalysisService(provider);
let failures = 0;
const check = (name, condition, detail = "") => {
  const mark = condition ? "ok" : "FAIL";
  process.stdout.write(
    `[${mark}] ${name}${detail === "" ? "" : ` — ${detail}`}\n`,
  );
  if (!condition) failures += 1;
};

const run = async (operation, input) => {
  const result = await service.execute(operation, input);
  if (!result.ok) {
    process.stdout.write(`[FAIL] ${operation} — ${result.error.message}\n`);
    failures += 1;
    return null;
  }
  return result.value.normalized_result;
};

if (options.apk !== null) {
  const { readFile } = await import("node:fs/promises");
  const identified = await run("identify_flutter_build", { path: options.apk });
  if (identified !== null) {
    const bytes = await stat(options.apk).then((info) => info.size);
    const digest = createHash("sha256")
      .update(await readFile(options.apk))
      .digest("hex");
    check(
      "target identity matches the file on disk",
      identified.target.bytes === bytes && identified.target.sha256 === digest,
      `${bytes} bytes`,
    );
    check(
      "Flutter payload detected",
      identified.flutter_detected === true,
      `${identified.abis.length} ABI(s)`,
    );
    const hashes = new Set(
      identified.abis
        .filter((abi) => abi.libapp.present)
        .map((abi) => abi.libapp.snapshot_hash),
    );
    check(
      "every ABI reports one agreeing snapshot hash",
      identified.abis
        .filter((abi) => abi.libapp.present)
        .every(
          (abi) =>
            abi.libapp.snapshot_hash !== null &&
            abi.libapp.snapshot_hash_sources === 2,
        ),
      `hash=${identified.abis.find((abi) => abi.libapp.present)?.libapp.snapshot_hash}`,
    );
    check(
      "every ABI agrees on one snapshot hash",
      hashes.size === 1,
      [...hashes].join(", "),
    );

    const libappAbis = identified.abis.filter((abi) => abi.libapp.present);
    check(
      "every Flutter ABI carries an engine with a hex build-id",
      libappAbis.length > 0 &&
        libappAbis.every(
          (abi) =>
            abi.libflutter.present &&
            abi.libflutter.build_id !== null &&
            /^[0-9a-f]{16,40}$/.test(abi.libflutter.build_id),
        ),
      libappAbis
        .map(
          (abi) =>
            `${abi.abi}:${abi.libflutter.present ? abi.libflutter.build_id?.slice(0, 12) : "missing"}`,
        )
        .join(", "),
    );

    const aot = await run("inspect_dart_aot", { path: options.apk });
    if (aot !== null) {
      check(
        "AOT snapshot sections located through the symbol table",
        aot.libapp.sections.length >= 4 &&
          aot.libapp.sections
            .filter((section) => section.name.endsWith("Data"))
            .every((section) => section.magic_valid),
        `${aot.libapp.sections.length} section(s), abi=${aot.abi}`,
      );
      check(
        "AOT hash agrees with the identification result",
        aot.libapp.snapshot_hash !== null &&
          aot.libapp.snapshot_hash ===
            identified.abis.find((abi) => abi.libapp.present)?.libapp
              .snapshot_hash,
      );
      check(
        "string pool exposes the dependency structure",
        aot.string_pool.package_uri_count_at_least > 100 &&
          aot.string_pool.dart_uri_count_at_least > 50,
        `${aot.string_pool.package_uri_count_at_least} package:, ${aot.string_pool.dart_uri_count_at_least} dart:`,
      );
    }

    // Exercise every ABI the APK carries, not only the preferred image.
    for (const abi of libappAbis) {
      if (abi.abi === aot?.abi) continue;
      const perAbi = await run("inspect_dart_aot", {
        path: options.apk,
        abi: abi.abi,
      });
      if (perAbi === null) continue;
      check(
        `AOT snapshot sections located through the symbol table for ${abi.abi}`,
        perAbi.abi === abi.abi &&
          perAbi.libapp.sections.length >= 4 &&
          perAbi.libapp.sections
            .filter((section) => section.name.endsWith("Data"))
            .every((section) => section.magic_valid),
        `${perAbi.libapp.sections.length} section(s), abi=${perAbi.abi}`,
      );
    }
  }
}

if (options.plainApk !== null) {
  const negative = await run("identify_flutter_build", {
    path: options.plainApk,
  });
  if (negative !== null)
    check(
      "non-Flutter APK reports not detected with complete coverage",
      negative.flutter_detected === false && negative.coverage === "complete",
    );
}

try {
  await provider.close();
} catch (cause) {
  failures += 1;
  process.stdout.write(
    `[FAIL] provider close retained cleanup — ${cause instanceof Error ? cause.message : String(cause)}\n`,
  );
}

if (options.apk === null) {
  process.stderr.write(
    "No Flutter APK was provided; pass --apk PATH to run the real verification.\n",
  );
  process.exit(2);
}
if (failures > 0) {
  process.stdout.write(`\n${failures} check(s) failed\n`);
  process.exit(1);
}
process.stdout.write("\nall flutter checks passed\n");

function parseArguments(argv) {
  const parsed = { help: false, apk: null, plainApk: null };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--help" || argument === "-h") parsed.help = true;
    else if (argument === "--apk") {
      parsed.apk = argv[index + 1] ?? null;
      index += 1;
    } else if (argument === "--plain-apk") {
      parsed.plainApk = argv[index + 1] ?? null;
      index += 1;
    } else {
      process.stderr.write(`unknown argument: ${argument}\n`);
      process.exit(2);
    }
  }
  return parsed;
}
