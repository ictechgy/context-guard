'use strict';

const childProcess = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PYTHON_ENV = 'CONTEXT_GUARD_RECEIPT_PYTHON';
const PACKAGE_PROTOCOL = 'contextguard-receipt-launch/v1';
const RESPONSE_SCHEMA_VERSION = 'contextguard-receipt-cli-response/v1';
const PYTHON_ISOLATION_FLAGS = [
  '-I', '-S', '-B', '-X', 'pycache_prefix=/dev/null/contextguard-receipt-pycache',
];
const MAX_MANIFEST_BYTES = 128 * 1024;
const MAX_PACKAGE_FILE_BYTES = 4 * 1024 * 1024;
const MAX_CHILD_STREAM_BYTES = 2 * 1024 * 1024;
const MAX_BROKER_PROTOCOL_BYTES = 8 * 1024;
const BASH_REFERENCE_BROKER_READY = 'READY contextguard-bash-reference-broker/v1\n';
const BASH_REFERENCE_BROKER_TOKEN = '--private-bash-reference-broker-v1';
const PROBE_TIMEOUT_MILLISECONDS = 5000;
const INTERRUPT_GRACE_MILLISECONDS = 2500;
const INTERRUPT_KILL_WAIT_MILLISECONDS = 750;
const RUNTIME_DIRECTORIES = new Set(['bin', 'python', 'schemas']);
const SOURCE_ONLY_DIRECTORIES = new Set(['dev', 'scripts', 'tests']);
const EXPECTED_FILES = [
  'LICENSE',
  'NOTICE',
  'README.md',
  'bin/context-guard-receipt-mcp.cjs',
  'bin/context-guard-receipt.cjs',
  'bin/launcher.cjs',
  'package.json',
  'python/context_guard_receipt/__init__.py',
  'python/context_guard_receipt/assembly.py',
  'python/context_guard_receipt/blueprint.py',
  'python/context_guard_receipt/bootstrap.py',
  'python/context_guard_receipt/canonical.py',
  'python/context_guard_receipt/cleanup.py',
  'python/context_guard_receipt/cli.py',
  'python/context_guard_receipt/cli_io.py',
  'python/context_guard_receipt/contracts.py',
  'python/context_guard_receipt/cost_optimization.py',
  'python/context_guard_receipt/diagnostic_ledger.py',
  'python/context_guard_receipt/diagnostics.py',
  'python/context_guard_receipt/evidence_pack.py',
  'python/context_guard_receipt/execution_twin.py',
  'python/context_guard_receipt/expansion.py',
  'python/context_guard_receipt/external_approval.py',
  'python/context_guard_receipt/external_approval_v2.py',
  'python/context_guard_receipt/identity.py',
  'python/context_guard_receipt/mcp.py',
  'python/context_guard_receipt/merged_capture.py',
  'python/context_guard_receipt/net_efficiency.py',
  'python/context_guard_receipt/phase_evaluation.py',
  'python/context_guard_receipt/protection.py',
  'python/context_guard_receipt/receipts.py',
  'python/context_guard_receipt/reference_expiry.py',
  'python/context_guard_receipt/router.py',
  'python/context_guard_receipt/runner.py',
  'python/context_guard_receipt/sanitizer.py',
  'python/context_guard_receipt/store.py',
  'python/context_guard_receipt/tool_schemas.py',
  'schemas/assembly-receipt.schema.json',
  'schemas/blueprint-descriptor.schema.json',
  'schemas/capability-record.schema.json',
  'schemas/command-capture-receipt.schema.json',
  'schemas/diagnostic-ledger-entry.schema.json',
  'schemas/diagnostic-ledger-inspection.schema.json',
  'schemas/diagnostic-ledger-metadata.schema.json',
  'schemas/diagnostics-report.schema.json',
  'schemas/diagnostics-request.schema.json',
  'schemas/evidence-boundary.schema.json',
  'schemas/evidence-descriptor.schema.json',
  'schemas/evidence-pack.schema.json',
  'schemas/evidence-reference.schema.json',
  'schemas/expansion-envelope.schema.json',
  'schemas/expansion-refusal.schema.json',
  'schemas/external-approval-v2.schema.json',
  'schemas/external-approval.schema.json',
  'schemas/phase-evaluation-p2.schema.json',
  'schemas/phase-evaluation-p3.schema.json',
  'schemas/phase-evaluation-p4.schema.json',
  'schemas/phase-evaluation-p5.schema.json',
  'schemas/phase-evaluation-p6.schema.json',
  'schemas/phase-evaluation-result.schema.json',
  'schemas/protection-decision.schema.json',
  'schemas/reference-expiry-inspection.schema.json',
  'schemas/reference-expiry-metadata.schema.json',
  'schemas/reference-expiry-record.schema.json',
  'schemas/reference-expiry-request.schema.json',
  'schemas/reference-expiry-result.schema.json',
  'schemas/shadow-firewall-report.schema.json',
  'schemas/source-identity.schema.json',
  'schemas/store-commit.schema.json',
  'schemas/store-metadata.schema.json',
  'schemas/tool-schema-bundle.schema.json',
  'schemas/tool-schema-catalog-reference.schema.json',
  'schemas/tool-schema-descriptor.schema.json',
  'schemas/tool-schema-expansion-envelope.schema.json',
  'schemas/tool-schema-expansion-refusal.schema.json',
  'schemas/tool-schema-expansion-request.schema.json',
  'schemas/tool-schema-receipt.schema.json',
  'schemas/tool-schema-reference.schema.json',
  'schemas/twin-event.schema.json',
  'schemas/twin-metadata.schema.json',
  'schemas/twin-request.schema.json',
  'schemas/twin-result.schema.json',
  'schemas/twin-snapshot.schema.json',
  'schemas/typed-blueprint.schema.json',
];
const TRUSTED_EXECUTABLE_FILES = new Set([
  'bin/context-guard-receipt-mcp.cjs',
  'bin/context-guard-receipt.cjs',
]);
// The installed launcher is part of the caller's/package manager's trust
// boundary. These embedded values prevent a mutable sidecar manifest alone
// from authorizing rewritten payloads; they are not a signature.
const TRUSTED_PAYLOAD_DIGESTS = {
  'LICENSE': 'c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4',
  'NOTICE': '40978c42e96a7b452cb77ef41f28961ca880e46ee7fa7c9589afa4d532655779',
  'README.md': 'bd598143ad96a744b9b67772c4197a14aee6fe4003d9804666af2b4f33dcb5a4',
  'bin/context-guard-receipt-mcp.cjs': '883b893d5ee484d63b78174ace60e171dc26e032d05dd19298fb6d6c5229cffd',
  'bin/context-guard-receipt.cjs': 'bdab50b0476e40024ea64f1f6cd0a46260b4707e2297d212bf5034cfd5a87ff8',
  'package.json': '36349b3f8dbab6be52788afdfa033b06863292540e0ada51fab1886f34474c5d',
  'python/context_guard_receipt/__init__.py': '1046588c63e24a72c3a57ab0ebd6d60d86c158358b5bbd50ca15cf26322fabc6',
  'python/context_guard_receipt/assembly.py': '0e28b6e0874477314436eecb532c767d61efe6d506ae8f79d98fae4b41dd35ea',
  'python/context_guard_receipt/blueprint.py': 'f4b8b617832ebe4bd5dc585f762a20b71b37ce79d54b6cd751f1e5fde5b785f0',
  'python/context_guard_receipt/bootstrap.py': 'fa846a8968c5199618ab68a86424c0cb88c32250291faf3ac37f26d14d4b018e',
  'python/context_guard_receipt/canonical.py': '91b57a1ebf2cc8fa0025ccfc8eaf6f50bc9363e6d3bc05c517b2014bf8a590c7',
  'python/context_guard_receipt/cleanup.py': '092d245e3f8534a40431997ed006a1e801a34d323aed9c54d921c3072e495ea2',
  'python/context_guard_receipt/cli.py': '8375084fc2c8d5099982e1cd28bed36745cacbe006b6fdbed1148b6dae3d0335',
  'python/context_guard_receipt/cli_io.py': '2de5ef56762e015264527306f19b1b72995cc3fffd8cd6cb58c8206e255c5baf',
  'python/context_guard_receipt/contracts.py': '1127a9b90bf2da63a097b066c7f1678109dcf622f40dd6746ef055aa7a98e39e',
  'python/context_guard_receipt/cost_optimization.py': '38432aa4cf2cfc104eef153017e204c9b3889abfdc6e37e66bf26a24f85460af',
  'python/context_guard_receipt/diagnostic_ledger.py': '3cc7865709c273b72136c48b1026ed5cd2830ea1bf76da4e424da08ccc13499d',
  'python/context_guard_receipt/diagnostics.py': '9a95f511b639091d0aacef69c0d4a311ad81e5a97299ab45ddc7fc23579e0e52',
  'python/context_guard_receipt/evidence_pack.py': '3fb5540dcee31cd6ded4883e4f4c99fb89ee17c2484f3e2ee33ebe741454d0f8',
  'python/context_guard_receipt/execution_twin.py': '510239b13c37ef15dcc838222b07ada49877e5540c351a51a121983b1fe031af',
  'python/context_guard_receipt/expansion.py': '9b848e555f05a621665c6b167a49e5d8085ffc9c6906f040f43fd2a87e981f2b',
  'python/context_guard_receipt/external_approval.py': '809405655f7b171f7b564f5ad381ae88237e325e1fe3a7e2bbb9f1442d20c6d0',
  'python/context_guard_receipt/external_approval_v2.py': '67e3d487a3df42bb30d7debf8f7fa7e85d62c75c62cd3a7308babaa92fae189a',
  'python/context_guard_receipt/identity.py': '31d4a0ba5e2a04b277a027a872ee0172c5d27ed09b60c41f53f286dd2d8b963c',
  'python/context_guard_receipt/mcp.py': 'cb3519972570d5b364cf8fa17d21554f21e5b5c9dbd86cc82380a33f18ea100e',
  'python/context_guard_receipt/merged_capture.py': 'a19c605a47b666f302b8b993d1e0973bfded46c1974022c2620c5ef5d598b7cf',
  'python/context_guard_receipt/net_efficiency.py': 'aff33babe06a3ecbaf682f325a0e10a2cbf785da7a53dfdc47e7d8d56f8dd88a',
  'python/context_guard_receipt/phase_evaluation.py': '2ee911bb898e28d5ba23e7bd3599a41125a0e7d13c9e4c9359a84e7ff721dc46',
  'python/context_guard_receipt/protection.py': '67ae06abb102292b3db09a6731a4aab90b3bc6ceb6dbe836fc636f82f783c347',
  'python/context_guard_receipt/receipts.py': '11c02d9df36be0dec2316594fd083ec39a1284325ded440de075081d2e56ddb0',
  'python/context_guard_receipt/reference_expiry.py': '2445292456776d5fcbf789f75a71781d64f12865958249d192cfc5a5ff27f2f6',
  'python/context_guard_receipt/router.py': '3f04337abde734cb2b9a52e7d7acb1d0ab27e2d4df997d9c9f121a22e4f400b5',
  'python/context_guard_receipt/runner.py': '05659031a491b89d93f7bd4d5d69d122cd51fa511100021c727e6939a2b822c1',
  'python/context_guard_receipt/sanitizer.py': 'ddf7d4d81dbb73156fa2274c7adf06475c4688b1e08341835aff4eeb81a72fc8',
  'python/context_guard_receipt/store.py': '69297a8f4efd68e8c2cdbd555d8b006d2c904369833d68dae53167fa22d1e877',
  'python/context_guard_receipt/tool_schemas.py': 'f84a8bc2f2232250dfe0782aaddf35c9842720f4815c6d2d8e4bd95757546bbc',
  'schemas/assembly-receipt.schema.json': '05ab76b261ca18ed8d165cb4e43395006e7196fdeccb53603c3ed77ca3bdfe88',
  'schemas/blueprint-descriptor.schema.json': '4424c2c482dc8d4184f1bd7ac6e1e45ad4ee36ee97da13e75b0986b2da8c9b09',
  'schemas/capability-record.schema.json': '86df8398c5199a0d4e3d58ee7d8e2a4171e0103a5ea05644f00f1c343889c114',
  'schemas/command-capture-receipt.schema.json': '7bcdaeb52fdfa4cbb3dc57b8d4b3b1cfa318bb7d8af11574ae0e23126ffa954b',
  'schemas/diagnostic-ledger-entry.schema.json': '8ea3ee4db48fb6d54b1bb613253f3313a38d33516ff328887feb6dfcc5c6c2ef',
  'schemas/diagnostic-ledger-inspection.schema.json': '2258c63aba7ada14949fe7db2e757d42551009d026d3152e3d95191c934b110f',
  'schemas/diagnostic-ledger-metadata.schema.json': '2ab1092790c97e0aa9439dd6f1f59004368a9e71e9b7dc1d849a2d2f59369e2a',
  'schemas/diagnostics-report.schema.json': 'b779475abbfdd76c9b6fca8f39b9b0c4e058f8e65a0ff9d7f583a1b8b01db38c',
  'schemas/diagnostics-request.schema.json': '7779d364170db90b8e7b71a342156d0b5bb0fe8ff8b423c21df29005d7efa2b4',
  'schemas/evidence-boundary.schema.json': 'b510303bd09adcaf7150415aab5cae3adbe4c99b8482c07a45bb978ad4e82ba7',
  'schemas/evidence-descriptor.schema.json': '29fa127eeafb8c52c05c7cdc8b1b929919e47e8e94aa8a5e6cd81ea2cf973dff',
  'schemas/evidence-pack.schema.json': '5ff6823d166b245a488e6d0f96512ae025b7836f7f46e5e14dc4508edfad6692',
  'schemas/evidence-reference.schema.json': 'f94fa353dac99a08793461ca9ec72962ce12de2e5328f94039048190db70071e',
  'schemas/expansion-envelope.schema.json': 'f838f84a06a433e62706467aa40097194f458bb2b3d42c600159558bed292d71',
  'schemas/expansion-refusal.schema.json': 'c5196da89d9b96349deb4c2c0ad2970d6f27d7760f9236b6d07d702443ee9da0',
  'schemas/external-approval.schema.json': 'c535d464311d9f7dd5b326face7596e6b930da4fb3e0350a5d3e0942e735eb69',
  'schemas/external-approval-v2.schema.json': 'd82bf2ea94d63bc6f1840b607167167891e767a13839d52c9debbbe046c62158',
  'schemas/phase-evaluation-p2.schema.json': 'd4390e71109e2704c4bc6f0935997d2b4b3f7d7cfc49ed92ef05e27eb21807bd',
  'schemas/phase-evaluation-p3.schema.json': 'ac0687ce2cd43ec4954d3fb0a876284fa75829435244913b5f81b275a4c234d7',
  'schemas/phase-evaluation-p4.schema.json': '05bf46ffad4d2d7ce7c0af623a6d57cdc3ce79baede3f1a005b5562966033580',
  'schemas/phase-evaluation-p5.schema.json': 'b4e7f888c8a041065af130c808d8bb47c5eb42e395e18d8f8c53ea4c7eac1457',
  'schemas/phase-evaluation-p6.schema.json': 'ed19929a20da8609c472f2d96ca5de9e32f7d32365b640876c9dbb22d9e33b00',
  'schemas/phase-evaluation-result.schema.json': 'a608f3426c7a4814f7d081be2963b979d03e895a6e44e85058aa67ead43368af',
  'schemas/protection-decision.schema.json': 'e7cf1b413d286347fda8f0f3a993676212e257f7e280757657032c23b5f9415f',
  'schemas/reference-expiry-inspection.schema.json': '6f862e4e39ebb09e14952b542d4a28a52c618900ecfa07dca063846c638721e1',
  'schemas/reference-expiry-metadata.schema.json': 'a72ed7c5f422732437cdc9e61e00efc5ea7e765c74955243f5b11b8a6eb12a73',
  'schemas/reference-expiry-record.schema.json': '450940d3f9d6d0baf7540c2bb2269f23ce8c53106658d7e9fdfe80392b7bad0e',
  'schemas/reference-expiry-request.schema.json': '9b96d2dac7ed9e23af17fbcb9311b4d2a5f3c7c04d042de380af3732887d6c89',
  'schemas/reference-expiry-result.schema.json': 'ed0c72aed6f21fdd3d78332768981da8db19e69a130cb881d3b86b7d61c13d82',
  'schemas/shadow-firewall-report.schema.json': '016a0d7320b9dc8c444f7488fdcd8bd33752fcfd27c1e906741972b9de50d04c',
  'schemas/source-identity.schema.json': 'c20007a9a03e8168feb7b413e035e1d3ef2cdad23a7c404dc25014a03411b047',
  'schemas/store-commit.schema.json': 'e078e14eade2395772936ecd8ec8a9add8b4a71ea45a1b6935645a83a46147ad',
  'schemas/store-metadata.schema.json': 'be6a83707fa541436e5930e444cfc6431d618ef65f561718a5ed66bf42f447db',
  'schemas/tool-schema-bundle.schema.json': 'bebb1d2ef79cfd76a870f6be554f7e1708e5015912885adc720ab3bc9495428d',
  'schemas/tool-schema-catalog-reference.schema.json': '306109a80512c6c6685bfcc00592fd81961030c459115717775ead6d79e8b4e7',
  'schemas/tool-schema-descriptor.schema.json': '1ebf3da9f7e81fc7de2eb9c19769011e6dbb590323a17a1febb2def9c85d3c87',
  'schemas/tool-schema-expansion-envelope.schema.json': '870aaafcd8e40bad739ebd9de316fe4ef15dc2e46ccee015dcb9ad1d886b68d2',
  'schemas/tool-schema-expansion-refusal.schema.json': 'e2bc67e71069d3f4c493db4e4aa946d65ee037eded5963ba00bf5c6bae51eefd',
  'schemas/tool-schema-expansion-request.schema.json': '0f21e070d4480279a849ba510c74cd26df8a1f8c0cfed5f0e7f73d6b9079dc39',
  'schemas/tool-schema-receipt.schema.json': '08621631baf4bc9abd01681c7e5194a73c6d7dd6f42571e7b91baffe323e2745',
  'schemas/tool-schema-reference.schema.json': '09f047b9d935e49e9b50e8e13e792a99bfe72eb356c1ad87e51dc0d0ac47f571',
  'schemas/twin-event.schema.json': 'fb74363bd595b8f8034ba33622bfa4018f566b75491232b462e8674de13671fb',
  'schemas/twin-metadata.schema.json': 'ab137d319fd151beaf9ae595633ab2d2be748b4efb6e1636b3052b663da6f9b8',
  'schemas/twin-request.schema.json': '0955de5d331555fb5662a3038022df6a7cf679692f77d4747923fbd9121d9acd',
  'schemas/twin-result.schema.json': '14b7cec1a2818d1fa0fac61b05dd77ffc683a01812372b64a8c5f24660b73735',
  'schemas/twin-snapshot.schema.json': 'c80da58c9c3ef2d49fdf0527d3310b611c87fde6c9fc6e9ee889d2cb127b65ff',
  'schemas/typed-blueprint.schema.json': 'd784099a65a700d9e9e72ea6993b8480c9bf7c7efa2f222a7f341a271526b97c',
};
const EVIDENCE_BOUNDARY = {
  evidence_class: 'companion_local_receipt_only',
  host_request_owned: false,
  provider_claim_authority: false,
  provider_join_status: 'missing',
  runtime_observer_present: false,
  schema_version: 'contextguard-receipt-evidence-boundary/v1',
  selected_branch: 'S2-UNSUPPORTED',
  selected_transport: 'NONE',
  stage1_evidence: false,
  stage2_evidence: false,
};

function canonicalJson(value) {
  return `${JSON.stringify(value, Object.keys(value).sort())}\n`;
}

function stableJson(value) {
  if (Array.isArray(value)) {
    return `[${value.map(stableJson).join(',')}]`;
  }
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function launcherErrorBytes(reason) {
  return Buffer.from(`${stableJson({
    evidence_boundary: EVIDENCE_BOUNDARY,
    operation: 'launcher',
    reason,
    schema_version: RESPONSE_SCHEMA_VERSION,
    status: 'error',
  })}\n`, 'ascii');
}

function launcherError(reason, exitCode) {
  const ignoreWriteError = () => {};
  process.stderr.once('error', ignoreWriteError);
  try {
    process.stderr.write(launcherErrorBytes(reason), () => {
      process.stderr.removeListener('error', ignoreWriteError);
    });
  } catch (_) {
    process.stderr.removeListener('error', ignoreWriteError);
  }
  return exitCode;
}

function mcpUsageError() {
  const payload = Buffer.from(`${stableJson({
    evidence_boundary: EVIDENCE_BOUNDARY,
    operation: 'mcp',
    reason: 'usage',
    schema_version: RESPONSE_SCHEMA_VERSION,
    status: 'error',
  })}\n`, 'ascii');
  const ignoreWriteError = () => {};
  process.stderr.once('error', ignoreWriteError);
  try {
    process.stderr.write(payload, () => {
      process.stderr.removeListener('error', ignoreWriteError);
    });
  } catch (_) {
    process.stderr.removeListener('error', ignoreWriteError);
  }
  return 64;
}

function writeExact(stream, payload) {
  if (payload.length === 0) return Promise.resolve(true);
  return new Promise((resolve) => {
    let settled = false;
    const finish = (succeeded) => {
      if (settled) return;
      settled = true;
      setImmediate(() => stream.removeListener('error', onError));
      resolve(succeeded);
    };
    const onError = () => finish(false);
    stream.on('error', onError);
    try {
      stream.write(payload, (error) => finish(!error));
    } catch (_) {
      finish(false);
    }
  });
}

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function isRegularFile(filePath) {
  try {
    return fs.lstatSync(filePath).isFile() && !fs.lstatSync(filePath).isSymbolicLink();
  } catch (_) {
    return false;
  }
}

function boundedFile(filePath, maximumBytes) {
  try {
    const metadata = fs.lstatSync(filePath);
    if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size > maximumBytes) {
      return null;
    }
    return fs.readFileSync(filePath);
  } catch (_) {
    return null;
  }
}

function validateIgnoredBytecodeCache(packageRoot, cacheDirectory) {
  const parentRelative = path.relative(packageRoot, path.dirname(cacheDirectory))
    .split(path.sep).join('/');
  if (!parentRelative.startsWith('python/')) return false;
  let entries;
  try {
    entries = fs.readdirSync(cacheDirectory, { withFileTypes: true });
  } catch (_) {
    return false;
  }
  for (const entry of entries) {
    const match = /^([A-Za-z0-9_]+)\.cpython-[0-9]+(?:\.opt-[0-9]+)?\.pyc$/.exec(entry.name);
    const candidate = path.join(cacheDirectory, entry.name);
    let metadata;
    try {
      metadata = fs.lstatSync(candidate);
    } catch (_) {
      return false;
    }
    if (!match || metadata.isSymbolicLink() || !metadata.isFile()
        || metadata.size > MAX_PACKAGE_FILE_BYTES
        || !EXPECTED_FILES.includes(`${parentRelative}/${match[1]}.py`)) {
      return false;
    }
  }
  return true;
}

function validateClosedRuntimeTree(packageRoot) {
  const expectedRuntimeFiles = new Set([...EXPECTED_FILES, 'package-files.json']);
  const expectedRootFiles = new Set(
    [...expectedRuntimeFiles].filter((entry) => !entry.includes('/')),
  );
  let topLevel;
  try {
    topLevel = fs.readdirSync(packageRoot, { withFileTypes: true });
  } catch (_) {
    return false;
  }
  for (const entry of topLevel) {
    const candidate = path.join(packageRoot, entry.name);
    if (expectedRootFiles.has(entry.name)) {
      if (!isRegularFile(candidate)) return false;
    } else if (RUNTIME_DIRECTORIES.has(entry.name) || SOURCE_ONLY_DIRECTORIES.has(entry.name)) {
      try {
        if (!fs.lstatSync(candidate).isDirectory() || fs.lstatSync(candidate).isSymbolicLink()) {
          return false;
        }
      } catch (_) {
        return false;
      }
    } else {
      return false;
    }
  }

  const actualRuntimeFiles = [];
  const pending = [...RUNTIME_DIRECTORIES].map((directory) => path.join(packageRoot, directory));
  while (pending.length > 0) {
    const directory = pending.pop();
    let entries;
    try {
      entries = fs.readdirSync(directory, { withFileTypes: true });
    } catch (_) {
      return false;
    }
    for (const entry of entries) {
      const candidate = path.join(directory, entry.name);
      let metadata;
      try {
        metadata = fs.lstatSync(candidate);
      } catch (_) {
        return false;
      }
      if (metadata.isSymbolicLink()) return false;
      if (metadata.isDirectory()) {
        if (entry.name === '__pycache__') {
          if (!validateIgnoredBytecodeCache(packageRoot, candidate)) return false;
        } else {
          pending.push(candidate);
        }
      } else if (metadata.isFile()) {
        actualRuntimeFiles.push(path.relative(packageRoot, candidate).split(path.sep).join('/'));
      } else {
        return false;
      }
    }
  }
  const expectedNestedFiles = [...expectedRuntimeFiles].filter((entry) => entry.includes('/'));
  return actualRuntimeFiles.sort().join('\n') === expectedNestedFiles.sort().join('\n');
}

function validatePackage(packageRoot) {
  const manifestPath = path.join(packageRoot, 'package-files.json');
  if (!validateClosedRuntimeTree(packageRoot)) {
    return false;
  }
  const manifestBytes = boundedFile(manifestPath, MAX_MANIFEST_BYTES);
  if (manifestBytes === null) return false;
  let manifest;
  try {
    manifest = JSON.parse(manifestBytes.toString('utf8'));
  } catch (_) {
    return false;
  }
  if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)
      || Object.keys(manifest).sort().join(',') !== 'files,schema_version'
      || manifest.schema_version !== 'contextguard-receipt-package-files/v1'
      || !Array.isArray(manifest.files)
      || manifest.files.length !== EXPECTED_FILES.length) {
    return false;
  }
  const paths = [];
  for (const entry of manifest.files) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)
        || Object.keys(entry).sort().join(',') !== 'mode,path,sha256'
        || typeof entry.path !== 'string' || typeof entry.mode !== 'string'
        || typeof entry.sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(entry.sha256)
        || !/^[0-7]{4}$/.test(entry.mode)
        || entry.mode !== (TRUSTED_EXECUTABLE_FILES.has(entry.path) ? '0755' : '0644')
        || path.posix.normalize(entry.path) !== entry.path || entry.path.startsWith('/')
        || entry.path.split('/').includes('..')) {
      return false;
    }
    paths.push(entry.path);
    const candidate = path.join(packageRoot, ...entry.path.split('/'));
    const fileBytes = boundedFile(candidate, MAX_PACKAGE_FILE_BYTES);
    if (fileBytes === null) {
      return false;
    }
    const mode = (fs.statSync(candidate).mode & 0o7777).toString(8).padStart(4, '0');
    const digest = crypto.createHash('sha256').update(fileBytes).digest('hex');
    if (!isPortablePackageMode(mode, entry.mode) || digest !== entry.sha256) {
      return false;
    }
    if (entry.path !== 'bin/launcher.cjs'
        && TRUSTED_PAYLOAD_DIGESTS[entry.path] !== digest) {
      return false;
    }
  }
  return paths.join('\n') === EXPECTED_FILES.join('\n')
    && Object.keys(TRUSTED_PAYLOAD_DIGESTS).sort().join('\n')
      === EXPECTED_FILES.filter((entry) => entry !== 'bin/launcher.cjs').sort().join('\n');
}

function isPortablePackageMode(observedMode, archiveMode) {
  if (archiveMode === '0644') {
    return observedMode === '0600' || observedMode === '0640' || observedMode === '0644';
  }
  if (archiveMode === '0755') {
    return observedMode === '0700' || observedMode === '0750' || observedMode === '0755';
  }
  return false;
}

function effectiveCredentials() {
  try {
    if (typeof process.geteuid !== 'function'
        || typeof process.getegid !== 'function'
        || typeof process.getgroups !== 'function') {
      return null;
    }
    const effectiveUid = process.geteuid();
    const effectiveGid = process.getegid();
    const groups = process.getgroups();
    if (!Number.isSafeInteger(effectiveUid) || effectiveUid < 0
        || !Number.isSafeInteger(effectiveGid) || effectiveGid < 0
        || !Array.isArray(groups)
        || groups.some((group) => !Number.isSafeInteger(group) || group < 0)) {
      return null;
    }
    const supplementaryGroups = [...new Set(groups.map((group) => BigInt(group)))]
      .sort((left, right) => (left < right ? -1 : left > right ? 1 : 0));
    return Object.freeze({
      effectiveGid: BigInt(effectiveGid),
      effectiveUid: BigInt(effectiveUid),
      supplementaryGroups: Object.freeze(supplementaryGroups),
    });
  } catch (_) {
    return null;
  }
}

function sameEffectiveCredentials(expected, observed) {
  return observed !== null
    && observed.effectiveUid === expected.effectiveUid
    && observed.effectiveGid === expected.effectiveGid
    && observed.supplementaryGroups.length === expected.supplementaryGroups.length
    && observed.supplementaryGroups.every(
      (group, index) => group === expected.supplementaryGroups[index],
    );
}

function executableByEffectiveCredentials(metadata, credentials) {
  if (credentials.effectiveUid === 0n) return (metadata.mode & 0o111n) !== 0n;
  if (metadata.uid === credentials.effectiveUid) return (metadata.mode & 0o100n) !== 0n;
  if (metadata.gid === credentials.effectiveGid
      || credentials.supplementaryGroups.includes(metadata.gid)) {
    return (metadata.mode & 0o010n) !== 0n;
  }
  return (metadata.mode & 0o001n) !== 0n;
}

function nativeExecutableRegularFile(
  candidate,
  allowCallerSelectedMetadata = false,
  expectedCredentials = undefined,
) {
  const credentials = expectedCredentials === undefined
    ? effectiveCredentials()
    : expectedCredentials;
  if (credentials === null) return null;
  if (!Number.isInteger(fs.constants.O_NOFOLLOW)) return null;

  let descriptor = null;
  let snapshot = null;
  let closed = false;
  try {
    descriptor = fs.openSync(
      candidate,
      fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW,
    );
    const metadata = fs.fstatSync(descriptor, { bigint: true });
    if (!metadata.isFile()
        || !executableByEffectiveCredentials(metadata, credentials)
        || (!allowCallerSelectedMetadata && (metadata.mode & 0o022n) !== 0n)
        || (!allowCallerSelectedMetadata
          && metadata.uid !== 0n
          && metadata.uid !== credentials.effectiveUid)) {
      return null;
    }
    const magic = Buffer.alloc(4);
    if (fs.readSync(descriptor, magic, 0, magic.length, 0) !== magic.length) return null;
    const signature = magic.readUInt32BE(0);
    if (signature !== 0x7f454c46
        && !new Set([
          0xfeedface, 0xcefaedfe, 0xfeedfacf, 0xcffaedfe,
          0xcafebabe, 0xbebafeca, 0xcafebabf, 0xbfbafeca,
        ]).has(signature)) {
      return null;
    }
    const fields = [
      'dev', 'ino', 'mode', 'uid', 'gid', 'nlink', 'size', 'mtimeNs', 'ctimeNs',
    ];
    if (fields.some((field) => typeof metadata[field] !== 'bigint')) return null;
    snapshot = Object.freeze(Object.fromEntries(
      fields.map((field) => [field, metadata[field]]),
    ));
  } catch (_) {
    return null;
  } finally {
    if (descriptor !== null) {
      try {
        fs.closeSync(descriptor);
        closed = true;
      } catch (_) {
        closed = false;
      }
    }
  }
  return closed ? snapshot : null;
}

function trustedRuntimeAncestry(executablePath, effectiveUid) {
  let current = path.dirname(executablePath);
  for (;;) {
    let metadata;
    try {
      metadata = fs.lstatSync(current, { bigint: true });
    } catch (_) {
      return false;
    }
    if (!metadata.isDirectory()
        || (metadata.uid !== 0n && metadata.uid !== effectiveUid)
        || ((metadata.mode & 0o022n) !== 0n && (metadata.mode & 0o1000n) === 0n)) {
      return false;
    }
    const parent = path.dirname(current);
    if (parent === current) return true;
    current = parent;
  }
}

function sameRuntimeSnapshot(expected, observed) {
  return [
    'dev', 'ino', 'mode', 'uid', 'gid', 'nlink', 'size', 'mtimeNs', 'ctimeNs',
  ].every((field) => observed[field] === expected[field]);
}

async function waitForShutdown(childClosed, milliseconds) {
  const deadline = Date.now() + milliseconds;
  do {
    if (childClosed()) return true;
    await delay(20);
  } while (Date.now() < deadline);
  return childClosed();
}

async function stopInterruptedChild(child, signalName, childClosed) {
  try {
    child.kill(signalName);
  } catch (_) {
    // The Python child may have completed immediately before the interrupt.
  }
  if (await waitForShutdown(childClosed, INTERRUPT_GRACE_MILLISECONDS)) {
    return false;
  }
  if (!childClosed()) {
    try {
      child.kill('SIGKILL');
    } catch (_) {
      // The Python child may have completed during the grace interval.
    }
  }
  await waitForShutdown(childClosed, INTERRUPT_KILL_WAIT_MILLISECONDS);
  return true;
}

function createSignalController() {
  let dispatch = null;
  let pendingSignals = [];
  let removed = false;

  const receive = (signalName, signalNumber) => {
    if (removed) return;
    if (dispatch !== null) {
      dispatch(signalName, signalNumber);
      return;
    }
    if (pendingSignals.length < 2) {
      pendingSignals.push({ signalName, signalNumber });
    }
  };
  const handleSigint = () => receive('SIGINT', 2);
  const handleSigterm = () => receive('SIGTERM', 15);
  process.on('SIGINT', handleSigint);
  process.on('SIGTERM', handleSigterm);

  return {
    bind(nextDispatch) {
      if (removed || dispatch !== null) return false;
      dispatch = nextDispatch;
      const queuedSignals = pendingSignals;
      pendingSignals = [];
      for (const pending of queuedSignals) {
        dispatch(pending.signalName, pending.signalNumber);
      }
      return true;
    },
    unbind(currentDispatch) {
      if (removed || dispatch !== currentDispatch) return;
      dispatch = null;
    },
    pending() {
      return removed ? 0 : pendingSignals.length;
    },
    takePending() {
      if (removed) return [];
      const queuedSignals = pendingSignals;
      pendingSignals = [];
      return queuedSignals;
    },
    remove() {
      if (removed) return;
      removed = true;
      dispatch = null;
      pendingSignals = [];
      process.removeListener('SIGINT', handleSigint);
      process.removeListener('SIGTERM', handleSigterm);
    },
  };
}

function finishQueuedSignals(signalController) {
  const queuedSignals = signalController.takePending();
  if (queuedSignals.length === 0) return false;
  signalController.remove();
  process.exitCode = queuedSignals.length === 1
    ? 128 + queuedSignals[0].signalNumber
    : launcherError('cleanup_unconfirmed', 69);
  return true;
}

function resolveExecutable(candidate, allowCallerSelectedMetadata = false) {
  try {
    const resolved = fs.realpathSync(candidate);
    const credentials = effectiveCredentials();
    if (credentials === null) return null;
    const snapshot = nativeExecutableRegularFile(
      resolved,
      allowCallerSelectedMetadata,
      credentials,
    );
    if (snapshot === null
        || (!allowCallerSelectedMetadata
          && !trustedRuntimeAncestry(resolved, credentials.effectiveUid))) {
      return null;
    }
    return Object.freeze({
      credentials,
      executablePath: resolved,
      explicit: allowCallerSelectedMetadata,
      snapshot,
    });
  } catch (_) {
    return null;
  }
}

function runtimeSelectionCurrent(selection) {
  const observedCredentials = effectiveCredentials();
  if (!sameEffectiveCredentials(selection.credentials, observedCredentials)) {
    return false;
  }
  if (!selection.explicit
      && !trustedRuntimeAncestry(
        selection.executablePath,
        observedCredentials.effectiveUid,
      )) {
    return false;
  }
  const observed = nativeExecutableRegularFile(
    selection.executablePath,
    selection.explicit,
    observedCredentials,
  );
  return observed !== null && sameRuntimeSnapshot(selection.snapshot, observed);
}

function privateBrokerInvocation(kind, argv) {
  if (kind !== 'receipt' || argv.length !== 11
      || argv[0] !== BASH_REFERENCE_BROKER_TOKEN
      || argv[1] !== '--capture-fd'
      || argv[3] !== '--transaction-id'
      || argv[5] !== '--root'
      || argv[7] !== '--state-dir'
      || argv[9] !== '--disclosure-days'
      || argv[10] !== '7'
      || !/^[0-9a-f]{64}$/.test(argv[4])) {
    return null;
  }
  const captureFd = Number(argv[2]);
  if (!/^[1-9][0-9]*$/.test(argv[2])
      || !Number.isSafeInteger(captureFd)
      || captureFd < 3
      || captureFd > 1048575) {
    return null;
  }
  for (const candidate of [argv[6], argv[8]]) {
    if (typeof candidate !== 'string' || candidate.length === 0
        || candidate.includes('\0') || !path.isAbsolute(candidate)
        || path.normalize(candidate) !== candidate) {
      return null;
    }
  }
  try {
    const metadata = fs.fstatSync(captureFd);
    if (!metadata.isFile()
        || metadata.uid !== process.geteuid()
        || (metadata.mode & 0o777) !== 0o600
        || metadata.nlink !== 0
        || metadata.size !== 0) {
      return null;
    }
  } catch (_) {
    return null;
  }
  return Object.freeze({
    captureFd,
    pythonArgv: Object.freeze([
      BASH_REFERENCE_BROKER_TOKEN,
      '--transaction-id', argv[4],
      '--root', argv[6],
      '--state-dir', argv[8],
      '--disclosure-days', '7',
    ]),
    transactionId: argv[4],
  });
}

function validPrivateBrokerProtocol(raw, transactionId) {
  let textValue;
  try {
    textValue = raw.toString('utf8');
    if (!Buffer.from(textValue, 'utf8').equals(raw)) return false;
  } catch (_) {
    return false;
  }
  if (textValue === BASH_REFERENCE_BROKER_READY) return true;
  if (!textValue.startsWith(BASH_REFERENCE_BROKER_READY + 'FINAL ')
      || !textValue.endsWith('\n')) {
    return false;
  }
  const finalText = textValue.slice(
    (BASH_REFERENCE_BROKER_READY + 'FINAL ').length,
    -1,
  );
  let result;
  try {
    result = JSON.parse(finalText);
  } catch (_) {
    return false;
  }
  return result !== null
    && typeof result === 'object'
    && !Array.isArray(result)
    && `${stableJson(result)}\n` === `${finalText}\n`
    && result.actionable === true
    && result.status === 'registered'
    && result.transaction_id === transactionId
    && Number.isSafeInteger(result.expires_at_unix_ms)
    && result.expires_at_unix_ms >= 0
    && typeof result.reference === 'string'
    && result.reference.length > 0;
}

function resolvePython() {
  const explicit = process.env[PYTHON_ENV];
  if (typeof explicit === 'string' && explicit.length > 0) {
    // An absolute override is an explicit caller trust decision. Managed tool
    // caches can expose trusted native runtimes with different ownership or
    // writable mode bits; automatic PATH discovery stays strict below.
    return path.isAbsolute(explicit) ? resolveExecutable(explicit, true) : null;
  }
  const pathValue = process.env.PATH || '';
  for (const directory of pathValue.split(path.delimiter)) {
    if (!directory || !path.isAbsolute(directory)) {
      continue;
    }
    const candidate = path.join(directory, 'python3');
    const resolved = resolveExecutable(candidate);
    if (resolved) {
      return resolved;
    }
  }
  return null;
}

function compatibleProbe(python, bootstrap, signalController) {
  return new Promise((resolve) => {
    let child = null;
    let childCloseOutcome = null;
    let completed = false;
    let interrupted = null;
    let interruptCleanup = null;
    let invalid = false;
    let killWaitTimer = null;
    let timer = null;
    let stdoutChunks = [];
    let stderrChunks = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;

    const discardOutput = () => {
      stdoutChunks = [];
      stderrChunks = [];
      stdoutBytes = 0;
      stderrBytes = 0;
    };
    const startInterruptCleanup = () => {
      if (child === null || interrupted === null || interruptCleanup !== null) return;
      if (timer !== null) {
        clearTimeout(timer);
        timer = null;
      }
      if (killWaitTimer !== null) {
        clearTimeout(killWaitTimer);
        killWaitTimer = null;
      }
      interruptCleanup = stopInterruptedChild(
        child,
        interrupted.signalName,
        () => childCloseOutcome !== null,
      );
      if (interrupted.escalationRequired) {
        try {
          child.kill('SIGKILL');
        } catch (_) {
          // The probe may have honored the first queued signal immediately.
        }
      }
      void (async () => {
        const escalationRequired = await interruptCleanup;
        finishProbe(null, {
          detachHandles: childCloseOutcome === null,
          unbindSignal: false,
        });
        signalController.remove();
        const expectedStatus = 128 + interrupted.signalNumber;
        const confirmedCleanup = !escalationRequired
          && !interrupted.escalationRequired
          && childCloseOutcome !== null
          && ((childCloseOutcome.status === expectedStatus
            && childCloseOutcome.signal === null)
            || (childCloseOutcome.status === null
              && childCloseOutcome.signal === interrupted.signalName));
        process.exitCode = confirmedCleanup
          ? expectedStatus
          : launcherError('cleanup_unconfirmed', 69);
      })();
    };
    const interrupt = (signalName, signalNumber) => {
      if (interrupted !== null) {
        interrupted.escalationRequired = true;
        if (child !== null) {
          try {
            child.kill('SIGKILL');
          } catch (_) {
            // A repeated interrupt is only an escalation request.
          }
        }
        return;
      }
      interrupted = { escalationRequired: invalid, signalName, signalNumber };
      discardOutput();
      startInterruptCleanup();
    };
    signalController.bind(interrupt);

    try {
      child = childProcess.spawn(
        python,
        [...PYTHON_ISOLATION_FLAGS, bootstrap, '--launcher-probe'],
        {
          stdio: ['ignore', 'pipe', 'pipe'],
          windowsHide: true,
        },
      );
    } catch (_) {
      if (interrupted === null) {
        signalController.unbind(interrupt);
        resolve(false);
      } else {
        signalController.remove();
        void Promise.resolve().then(() => {
          process.exitCode = launcherError('cleanup_unconfirmed', 69);
        });
        resolve(null);
      }
      return;
    }

    const failProbe = () => {
      if (completed || invalid || interrupted !== null) return;
      invalid = true;
      discardOutput();
      if (timer !== null) {
        clearTimeout(timer);
        timer = null;
      }
      try {
        child.kill('SIGKILL');
      } catch (_) {
        // A failed spawn may not have produced a process to stop.
      }
      if (completed) return;
      killWaitTimer = setTimeout(() => {
        if (completed) return;
        signalController.remove();
        process.exitCode = launcherError('cleanup_unconfirmed', 69);
        finishProbe(null, { detachHandles: true, unbindSignal: false });
      }, INTERRUPT_KILL_WAIT_MILLISECONDS);
    };
    const capture = (channel, chunk) => {
      if (invalid || interrupted !== null) return;
      const currentBytes = channel === 'stdout' ? stdoutBytes : stderrBytes;
      if (!Buffer.isBuffer(chunk) || currentBytes + chunk.length > 16 * 1024) {
        failProbe();
        return;
      }
      if (channel === 'stdout') {
        stdoutChunks.push(chunk);
        stdoutBytes += chunk.length;
      } else {
        stderrChunks.push(chunk);
        stderrBytes += chunk.length;
      }
    };
    const captureStdout = (chunk) => capture('stdout', chunk);
    const captureStderr = (chunk) => capture('stderr', chunk);
    const removeProbeListeners = () => {
      child.removeListener('error', failProbe);
      child.removeListener('close', handleClose);
      if (child.stdout !== null) {
        child.stdout.removeListener('data', captureStdout);
        child.stdout.removeListener('error', failProbe);
      }
      if (child.stderr !== null) {
        child.stderr.removeListener('data', captureStderr);
        child.stderr.removeListener('error', failProbe);
      }
    };
    const detachProbeHandles = () => {
      for (const stream of [child.stdout, child.stderr]) {
        if (stream !== null && typeof stream.destroy === 'function') {
          try {
            stream.destroy();
          } catch (_) {
            // The stream may already be detached from a failed child.
          }
        }
      }
      if (typeof child.unref === 'function') {
        try {
          child.unref();
        } catch (_) {
          // An already-closed child may reject a redundant unref.
        }
      }
    };
    const finishProbe = (
      outcome,
      { detachHandles = false, unbindSignal = true } = {},
    ) => {
      if (completed) return false;
      completed = true;
      if (timer !== null) {
        clearTimeout(timer);
        timer = null;
      }
      if (killWaitTimer !== null) {
        clearTimeout(killWaitTimer);
        killWaitTimer = null;
      }
      removeProbeListeners();
      if (detachHandles) detachProbeHandles();
      if (unbindSignal) signalController.unbind(interrupt);
      discardOutput();
      resolve(outcome);
      return true;
    };
    const handleClose = (status, childSignal) => {
      if (completed) return;
      childCloseOutcome = { signal: childSignal, status };
      if (interrupted !== null) {
        finishProbe(null, { unbindSignal: false });
        return;
      }
      if (invalid || status !== 0 || childSignal !== null || stderrBytes !== 0) {
        finishProbe(false);
        return;
      }
      const stdout = Buffer.concat(stdoutChunks, stdoutBytes).toString('utf8');
      let result;
      try {
        result = JSON.parse(stdout);
      } catch (_) {
        finishProbe(false);
        return;
      }
      const exactObject = result !== null
        && typeof result === 'object'
        && !Array.isArray(result);
      const resultKeys = exactObject ? Object.keys(result).sort() : [];
      finishProbe(exactObject
        && resultKeys.length === 3
        && resultKeys[0] === 'implementation'
        && resultKeys[1] === 'package_protocol'
        && resultKeys[2] === 'python_version'
        && result.implementation === 'CPython'
        && result.package_protocol === PACKAGE_PROTOCOL
        && Array.isArray(result.python_version)
        && result.python_version.length === 2
        && result.python_version[0] === 3
        && Number.isInteger(result.python_version[1])
        && result.python_version[1] >= 11 && result.python_version[1] < 15);
    };
    if (child.stdout === null || child.stderr === null) {
      failProbe();
    } else {
      child.stdout.on('data', captureStdout);
      child.stderr.on('data', captureStderr);
      child.stdout.on('error', failProbe);
      child.stderr.on('error', failProbe);
    }
    child.on('error', failProbe);
    child.once('close', handleClose);
    if (interrupted === null) {
      timer = setTimeout(failProbe, PROBE_TIMEOUT_MILLISECONDS);
    } else {
      startInterruptCleanup();
    }
  });
}

function monitorStreamingMcp(child, signalController) {
  if (child.stderr === null) {
    try {
      child.kill('SIGKILL');
    } catch (_) {
      // The failed launch may already have terminated.
    }
    signalController.remove();
    return launcherError('runtime_unavailable', 69);
  }

  let runtimeFailure = false;
  let interrupted = null;
  let childCloseOutcome = null;
  let completed = false;

  const failClosed = () => {
    if (runtimeFailure || completed) return;
    runtimeFailure = true;
    void stopInterruptedChild(child, 'SIGTERM', () => childCloseOutcome !== null);
  };
  child.stderr.on('data', failClosed);
  child.on('error', failClosed);

  const interrupt = (signalName, signalNumber) => {
    if (completed) return;
    if (interrupted !== null) {
      interrupted.escalationRequired = true;
      try {
        child.kill('SIGKILL');
      } catch (_) {
        // A repeated interrupt is only an escalation request.
      }
      return;
    }
    interrupted = { escalationRequired: false, signalNumber };
    void (async () => {
      const escalationRequired = await stopInterruptedChild(
        child,
        signalName,
        () => childCloseOutcome !== null,
      );
      completed = true;
      signalController.remove();
      const expectedStatus = 128 + interrupted.signalNumber;
      const confirmedCleanup = !escalationRequired
        && !interrupted.escalationRequired
        && childCloseOutcome !== null
        && ((childCloseOutcome.status === expectedStatus
          && childCloseOutcome.signal === null)
          || (childCloseOutcome.status === null
            && childCloseOutcome.signal === signalName));
      process.exitCode = confirmedCleanup
        ? expectedStatus
        : launcherError('cleanup_unconfirmed', 69);
    })();
  };

  child.on('close', (status, childSignal) => {
    childCloseOutcome = { signal: childSignal, status };
    if (interrupted !== null || completed) return;
    completed = true;
    signalController.remove();
    if (runtimeFailure || childSignal !== null || !Number.isInteger(status)) {
      process.exitCode = launcherError('runtime_unavailable', 69);
      return;
    }
    process.exitCode = status;
  });
  signalController.bind(interrupt);
  return undefined;
}

function monitorPrivateBroker(child, invocation, signalController) {
  if (child.stdin === null || child.stdout === null || child.stderr === null) {
    try {
      child.kill('SIGKILL');
    } catch (_) {
      // The failed launch may already have terminated.
    }
    signalController.remove();
    return launcherError('runtime_unavailable', 69);
  }
  let protocolChunks = [];
  let protocolBytes = 0;
  let runtimeFailure = false;
  let completed = false;
  let childCloseOutcome = null;
  let interrupted = null;

  const failClosed = () => {
    if (runtimeFailure || completed) return;
    runtimeFailure = true;
    protocolChunks = [];
    protocolBytes = 0;
    try {
      child.kill('SIGKILL');
    } catch (_) {
      // A concurrently closed broker needs no further cleanup.
    }
  };
  child.stdout.on('data', (chunk) => {
    if (runtimeFailure || interrupted !== null) return;
    if (!Buffer.isBuffer(chunk)
        || protocolBytes + chunk.length > MAX_BROKER_PROTOCOL_BYTES) {
      failClosed();
      return;
    }
    protocolChunks.push(chunk);
    protocolBytes += chunk.length;
    try {
      if (!process.stdout.write(chunk)) {
        child.stdout.pause();
        process.stdout.once('drain', () => child.stdout.resume());
      }
    } catch (_) {
      failClosed();
    }
  });
  child.stdout.on('error', failClosed);
  child.stderr.on('data', failClosed);
  child.stderr.on('error', failClosed);
  child.on('error', failClosed);
  child.stdin.on('error', failClosed);
  process.stdout.once('error', failClosed);
  process.stdin.pipe(child.stdin);

  const interrupt = (signalName, signalNumber) => {
    if (completed) return;
    if (interrupted !== null) {
      interrupted.escalationRequired = true;
      try {
        child.kill('SIGKILL');
      } catch (_) {
        // Repeated interruption is only an escalation request.
      }
      return;
    }
    interrupted = { escalationRequired: false, signalNumber };
    protocolChunks = [];
    protocolBytes = 0;
    void (async () => {
      const escalationRequired = await stopInterruptedChild(
        child,
        signalName,
        () => childCloseOutcome !== null,
      );
      completed = true;
      signalController.remove();
      const expectedStatus = 128 + signalNumber;
      const confirmedCleanup = !escalationRequired
        && !interrupted.escalationRequired
        && childCloseOutcome !== null
        && ((childCloseOutcome.status === expectedStatus
          && childCloseOutcome.signal === null)
          || (childCloseOutcome.status === null
            && childCloseOutcome.signal === signalName));
      process.exitCode = confirmedCleanup
        ? expectedStatus
        : launcherError('cleanup_unconfirmed', 69);
    })();
  };
  child.on('close', (status, childSignal) => {
    childCloseOutcome = { signal: childSignal, status };
    if (interrupted !== null || completed) return;
    completed = true;
    signalController.remove();
    process.stdout.removeListener('error', failClosed);
    const protocol = Buffer.concat(protocolChunks, protocolBytes);
    protocolChunks = [];
    protocolBytes = 0;
    if (runtimeFailure || childSignal !== null || status !== 0
        || !validPrivateBrokerProtocol(protocol, invocation.transactionId)) {
      process.exitCode = launcherError('runtime_unavailable', 69);
      return;
    }
    process.exitCode = 0;
  });
  signalController.bind(interrupt);
  return undefined;
}

function launch(kind, argv, entryFilename) {
  const packageRoot = path.dirname(path.dirname(fs.realpathSync(entryFilename)));
  if (!validatePackage(packageRoot)) {
    return launcherError('integrity_failure', 70);
  }
  const runtime = resolvePython();
  if (!runtime || !runtimeSelectionCurrent(runtime)) {
    return launcherError('runtime_unavailable', 69);
  }
  const bootstrap = path.join(packageRoot, 'python', 'context_guard_receipt', 'bootstrap.py');
  const signalController = createSignalController();
  void continueLaunch(kind, argv, runtime, bootstrap, signalController);
  return undefined;
}

async function continueLaunch(kind, argv, runtime, bootstrap, signalController) {
  const probeCompatible = await compatibleProbe(
    runtime.executablePath,
    bootstrap,
    signalController,
  );
  if (probeCompatible === null) return;
  if (finishQueuedSignals(signalController)) return;
  if (!probeCompatible) {
    signalController.remove();
    process.exitCode = launcherError('protocol_incompatible', 78);
    return;
  }
  const currentAfterProbe = runtimeSelectionCurrent(runtime);
  if (finishQueuedSignals(signalController)) return;
  if (!currentAfterProbe) {
    signalController.remove();
    process.exitCode = launcherError('runtime_unavailable', 69);
    return;
  }
  if (kind === 'mcp') {
    const rootInvocation = argv.length === 2
      && argv[0] === '--root'
      && typeof argv[1] === 'string'
      && argv[1].length > 0
      && !argv[1].includes('\0')
      && path.isAbsolute(argv[1])
      && path.normalize(argv[1]) === argv[1];
    const stateInvocation = argv.length === 4
      && argv[0] === '--root'
      && typeof argv[1] === 'string'
      && argv[1].length > 0
      && !argv[1].includes('\0')
      && path.isAbsolute(argv[1])
      && path.normalize(argv[1]) === argv[1]
      && argv[2] === '--state-dir'
      && typeof argv[3] === 'string'
      && argv[3].length > 0
      && !argv[3].includes('\0')
      && path.isAbsolute(argv[3])
      && path.normalize(argv[3]) === argv[3];
    if (!(argv.length === 1 && argv[0] === '--help') && !rootInvocation && !stateInvocation) {
      if (finishQueuedSignals(signalController)) return;
      signalController.remove();
      process.exitCode = mcpUsageError();
      return;
    }
  }
  const currentBeforeSpawn = runtimeSelectionCurrent(runtime);
  if (finishQueuedSignals(signalController)) return;
  if (!currentBeforeSpawn) {
    signalController.remove();
    process.exitCode = launcherError('runtime_unavailable', 69);
    return;
  }
  if (finishQueuedSignals(signalController)) return;
  const privateBroker = privateBrokerInvocation(kind, argv);
  let child;
  try {
    child = childProcess.spawn(
      runtime.executablePath,
      [
        ...PYTHON_ISOLATION_FLAGS,
        bootstrap,
        kind,
        ...(privateBroker === null ? argv : privateBroker.pythonArgv),
      ],
      {
        stdio: privateBroker !== null
          ? ['pipe', 'pipe', 'pipe', privateBroker.captureFd]
          : (kind === 'mcp'
            ? ['inherit', 'inherit', 'pipe']
            : ['inherit', 'pipe', 'pipe']),
        windowsHide: true,
      },
    );
  } catch (_) {
    const signalPending = signalController.pending() > 0;
    signalController.remove();
    process.exitCode = signalPending
      ? launcherError('cleanup_unconfirmed', 69)
      : launcherError('runtime_unavailable', 69);
    return;
  }
  if (kind === 'mcp') {
    const immediateExitCode = monitorStreamingMcp(child, signalController);
    if (Number.isInteger(immediateExitCode)) process.exitCode = immediateExitCode;
    return;
  }
  if (privateBroker !== null) {
    const immediateExitCode = monitorPrivateBroker(
      child, privateBroker, signalController,
    );
    if (Number.isInteger(immediateExitCode)) process.exitCode = immediateExitCode;
    return;
  }
  if (child.stdout === null || child.stderr === null) {
    try {
      child.kill('SIGKILL');
    } catch (_) {
      // The failed launch has no output channels to drain.
    }
    signalController.remove();
    process.exitCode = launcherError('runtime_unavailable', 69);
    return;
  }

  let stdoutChunks = [];
  let stderrChunks = [];
  let stdoutBytes = 0;
  let stderrBytes = 0;
  let runtimeFailure = false;
  let interrupted = null;
  let childCloseOutcome = null;
  let completed = false;

  const discardOutput = () => {
    stdoutChunks = [];
    stderrChunks = [];
    stdoutBytes = 0;
    stderrBytes = 0;
  };
  const capture = (channel, chunk) => {
    if (interrupted !== null || runtimeFailure) return;
    const currentBytes = channel === 'stdout' ? stdoutBytes : stderrBytes;
    if (!Buffer.isBuffer(chunk) || currentBytes + chunk.length > MAX_CHILD_STREAM_BYTES) {
      runtimeFailure = true;
      discardOutput();
      void stopInterruptedChild(child, 'SIGTERM', () => childCloseOutcome !== null);
      return;
    }
    if (channel === 'stdout') {
      stdoutChunks.push(chunk);
      stdoutBytes += chunk.length;
    } else {
      stderrChunks.push(chunk);
      stderrBytes += chunk.length;
    }
  };
  child.stdout.on('data', (chunk) => capture('stdout', chunk));
  child.stderr.on('data', (chunk) => capture('stderr', chunk));
  child.on('error', () => {
    runtimeFailure = true;
    discardOutput();
  });

  const interrupt = (signalName, signalNumber) => {
    if (completed) return;
    if (interrupted !== null) {
      interrupted.escalationRequired = true;
      try {
        child.kill('SIGKILL');
      } catch (_) {
        // A repeated interrupt is only an escalation request.
      }
      return;
    }
    interrupted = {
      escalationRequired: false,
      signalNumber,
    };
    discardOutput();
    void (async () => {
      const escalationRequired = await stopInterruptedChild(
        child,
        signalName,
        () => childCloseOutcome !== null,
      );
      completed = true;
      discardOutput();
      signalController.remove();
      const expectedStatus = 128 + interrupted.signalNumber;
      const confirmedCleanup = !escalationRequired
        && !interrupted.escalationRequired
        && childCloseOutcome !== null
        && ((childCloseOutcome.status === expectedStatus
          && childCloseOutcome.signal === null)
          || (childCloseOutcome.status === null
            && childCloseOutcome.signal === signalName));
      process.exitCode = confirmedCleanup
        ? expectedStatus
        : launcherError('cleanup_unconfirmed', 69);
    })();
  };

  child.on('close', (status, childSignal) => {
    childCloseOutcome = { signal: childSignal, status };
    if (interrupted !== null || completed) return;
    completed = true;
    signalController.remove();
    void (async () => {
      if (runtimeFailure || childSignal !== null || !Number.isInteger(status)) {
        discardOutput();
        process.exitCode = launcherError('runtime_unavailable', 69);
        return;
      }
      const stdout = Buffer.concat(stdoutChunks, stdoutBytes);
      const stderr = Buffer.concat(stderrChunks, stderrBytes);
      discardOutput();
      if (!(await writeExact(process.stdout, stdout))) {
        await writeExact(process.stderr, launcherErrorBytes('delivery_failure'));
        process.exitCode = 74;
        return;
      }
      if (!(await writeExact(process.stderr, stderr))) {
        process.exitCode = 74;
        return;
      }
      process.exitCode = status;
    })();
  });
  signalController.bind(interrupt);
}

module.exports = { launch };
