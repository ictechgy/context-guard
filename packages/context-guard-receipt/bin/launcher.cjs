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
  'python/context_guard_receipt/cli.py',
  'python/context_guard_receipt/cli_io.py',
  'python/context_guard_receipt/contracts.py',
  'python/context_guard_receipt/evidence_pack.py',
  'python/context_guard_receipt/expansion.py',
  'python/context_guard_receipt/identity.py',
  'python/context_guard_receipt/protection.py',
  'python/context_guard_receipt/receipts.py',
  'python/context_guard_receipt/router.py',
  'python/context_guard_receipt/store.py',
  'schemas/assembly-receipt.schema.json',
  'schemas/blueprint-descriptor.schema.json',
  'schemas/capability-record.schema.json',
  'schemas/evidence-boundary.schema.json',
  'schemas/evidence-descriptor.schema.json',
  'schemas/evidence-pack.schema.json',
  'schemas/evidence-reference.schema.json',
  'schemas/expansion-envelope.schema.json',
  'schemas/expansion-refusal.schema.json',
  'schemas/protection-decision.schema.json',
  'schemas/source-identity.schema.json',
  'schemas/store-commit.schema.json',
  'schemas/store-metadata.schema.json',
  'schemas/typed-blueprint.schema.json',
];
// The installed launcher is part of the caller's/package manager's trust
// boundary. These embedded values prevent a mutable sidecar manifest alone
// from authorizing rewritten payloads; they are not a signature.
const TRUSTED_PAYLOAD_DIGESTS = {
  'LICENSE': 'c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4',
  'NOTICE': '40978c42e96a7b452cb77ef41f28961ca880e46ee7fa7c9589afa4d532655779',
  'README.md': '79e43e661a23c6b9c24c6c637fe5660104781540c92419df6693ed1f6cb8cce8',
  'bin/context-guard-receipt-mcp.cjs': '883b893d5ee484d63b78174ace60e171dc26e032d05dd19298fb6d6c5229cffd',
  'bin/context-guard-receipt.cjs': 'bdab50b0476e40024ea64f1f6cd0a46260b4707e2297d212bf5034cfd5a87ff8',
  'package.json': 'b585d49acb0d92ca1b3365c2546260b0773a4ed6c969f8557ad6f5dd49f28ecf',
  'python/context_guard_receipt/__init__.py': '1046588c63e24a72c3a57ab0ebd6d60d86c158358b5bbd50ca15cf26322fabc6',
  'python/context_guard_receipt/assembly.py': '0e28b6e0874477314436eecb532c767d61efe6d506ae8f79d98fae4b41dd35ea',
  'python/context_guard_receipt/blueprint.py': 'f4b8b617832ebe4bd5dc585f762a20b71b37ce79d54b6cd751f1e5fde5b785f0',
  'python/context_guard_receipt/bootstrap.py': '334787a36bcb7a7441817e33c2dd7641bccac504b83e5117309a69acc87ad211',
  'python/context_guard_receipt/canonical.py': '91b57a1ebf2cc8fa0025ccfc8eaf6f50bc9363e6d3bc05c517b2014bf8a590c7',
  'python/context_guard_receipt/cli.py': '6a40e83ccdcc5c5055e2289e143cda46ec6b4d12050e13b93f67187149f57871',
  'python/context_guard_receipt/cli_io.py': '2de5ef56762e015264527306f19b1b72995cc3fffd8cd6cb58c8206e255c5baf',
  'python/context_guard_receipt/contracts.py': '1127a9b90bf2da63a097b066c7f1678109dcf622f40dd6746ef055aa7a98e39e',
  'python/context_guard_receipt/evidence_pack.py': '3fb5540dcee31cd6ded4883e4f4c99fb89ee17c2484f3e2ee33ebe741454d0f8',
  'python/context_guard_receipt/expansion.py': '9d102a2534312f20543e54faa192fda367445271079aeeb65b55664692c75046',
  'python/context_guard_receipt/identity.py': 'fc41f17612d75a4e9a37971e274d7e071bc144062ebb2011df4450ccac890a54',
  'python/context_guard_receipt/protection.py': '67ae06abb102292b3db09a6731a4aab90b3bc6ceb6dbe836fc636f82f783c347',
  'python/context_guard_receipt/receipts.py': '11c02d9df36be0dec2316594fd083ec39a1284325ded440de075081d2e56ddb0',
  'python/context_guard_receipt/router.py': '22b395d0a8a0522fcc9b12c1b12493e90aafb9e374937725a2bdaf223188529c',
  'python/context_guard_receipt/store.py': 'bfd70b5afec188518fc6b3a568ba9eb30d5fb874f99f8c538e51a462201336ce',
  'schemas/assembly-receipt.schema.json': '05ab76b261ca18ed8d165cb4e43395006e7196fdeccb53603c3ed77ca3bdfe88',
  'schemas/blueprint-descriptor.schema.json': '4424c2c482dc8d4184f1bd7ac6e1e45ad4ee36ee97da13e75b0986b2da8c9b09',
  'schemas/capability-record.schema.json': '2ad38d92d38effae26182fb698bae7b9e4a9435b0f7b142ac6efff4661bd4131',
  'schemas/evidence-boundary.schema.json': 'b510303bd09adcaf7150415aab5cae3adbe4c99b8482c07a45bb978ad4e82ba7',
  'schemas/evidence-descriptor.schema.json': '29fa127eeafb8c52c05c7cdc8b1b929919e47e8e94aa8a5e6cd81ea2cf973dff',
  'schemas/evidence-pack.schema.json': '5ff6823d166b245a488e6d0f96512ae025b7836f7f46e5e14dc4508edfad6692',
  'schemas/evidence-reference.schema.json': 'f94fa353dac99a08793461ca9ec72962ce12de2e5328f94039048190db70071e',
  'schemas/expansion-envelope.schema.json': 'f838f84a06a433e62706467aa40097194f458bb2b3d42c600159558bed292d71',
  'schemas/expansion-refusal.schema.json': 'c5196da89d9b96349deb4c2c0ad2970d6f27d7760f9236b6d07d702443ee9da0',
  'schemas/protection-decision.schema.json': 'e7cf1b413d286347fda8f0f3a993676212e257f7e280757657032c23b5f9415f',
  'schemas/source-identity.schema.json': 'c20007a9a03e8168feb7b413e035e1d3ef2cdad23a7c404dc25014a03411b047',
  'schemas/store-commit.schema.json': 'e078e14eade2395772936ecd8ec8a9add8b4a71ea45a1b6935645a83a46147ad',
  'schemas/store-metadata.schema.json': '60d36e2b6d07ba9c78b6916183c75d40aa3301dfcd453fcbafdf8e91282dbea7',
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

function launcherError(reason, exitCode) {
  process.stderr.write(`${stableJson({
    evidence_boundary: EVIDENCE_BOUNDARY,
    operation: 'launcher',
    reason,
    schema_version: RESPONSE_SCHEMA_VERSION,
    status: 'error',
  })}\n`);
  return exitCode;
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
    const mode = (fs.statSync(candidate).mode & 0o777).toString(8).padStart(4, '0');
    const digest = crypto.createHash('sha256').update(fileBytes).digest('hex');
    if (mode !== entry.mode || digest !== entry.sha256) {
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

function nativeExecutableRegularFile(candidate) {
  try {
    const metadata = fs.statSync(candidate);
    if (!metadata.isFile() || fs.lstatSync(candidate).isSymbolicLink()
        || (metadata.mode & 0o111) === 0 || (metadata.mode & 0o022) !== 0) {
      return false;
    }
    if (typeof process.getuid === 'function' && metadata.uid !== 0 && metadata.uid !== process.getuid()) {
      return false;
    }
    fs.accessSync(candidate, fs.constants.X_OK);
    const descriptor = fs.openSync(candidate, 'r');
    const magic = Buffer.alloc(4);
    try {
      if (fs.readSync(descriptor, magic, 0, magic.length, 0) !== magic.length) return false;
    } finally {
      fs.closeSync(descriptor);
    }
    const signature = magic.readUInt32BE(0);
    return signature === 0x7f454c46
      || new Set([
        0xfeedface, 0xcefaedfe, 0xfeedfacf, 0xcffaedfe,
        0xcafebabe, 0xbebafeca, 0xcafebabf, 0xbfbafeca,
      ]).has(signature);
  } catch (_) {
    return false;
  }
}

function resolveExecutable(candidate) {
  try {
    const resolved = fs.realpathSync(candidate);
    return nativeExecutableRegularFile(resolved) ? resolved : null;
  } catch (_) {
    return null;
  }
}

function resolvePython() {
  const explicit = process.env[PYTHON_ENV];
  if (typeof explicit === 'string' && explicit.length > 0) {
    return path.isAbsolute(explicit) ? resolveExecutable(explicit) : null;
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

function compatibleProbe(python, bootstrap) {
  const probe = childProcess.spawnSync(
    python,
    [...PYTHON_ISOLATION_FLAGS, bootstrap, '--launcher-probe'],
    {
      encoding: 'utf8',
      maxBuffer: 16 * 1024,
      windowsHide: true,
    },
  );
  if (probe.error || probe.status !== 0 || probe.stderr !== '') {
    return false;
  }
  let result;
  try {
    result = JSON.parse(probe.stdout);
  } catch (_) {
    return false;
  }
  return stableJson(result) === stableJson({
    implementation: 'CPython',
    package_protocol: PACKAGE_PROTOCOL,
    python_version: [3, result && result.python_version && result.python_version[1]],
  }) && Array.isArray(result.python_version)
    && result.python_version.length === 2
    && Number.isInteger(result.python_version[1])
    && result.python_version[1] >= 11 && result.python_version[1] < 15;
}

function launch(kind, argv, entryFilename) {
  const packageRoot = path.dirname(path.dirname(fs.realpathSync(entryFilename)));
  if (!validatePackage(packageRoot)) {
    return launcherError('integrity_failure', 70);
  }
  const python = resolvePython();
  if (!python) {
    return launcherError('runtime_unavailable', 69);
  }
  const bootstrap = path.join(packageRoot, 'python', 'context_guard_receipt', 'bootstrap.py');
  if (!compatibleProbe(python, bootstrap)) {
    return launcherError('protocol_incompatible', 78);
  }
  const child = childProcess.spawnSync(python, [...PYTHON_ISOLATION_FLAGS, bootstrap, kind, ...argv], {
    maxBuffer: 2 * 1024 * 1024,
    stdio: ['inherit', 'pipe', 'pipe'],
    windowsHide: true,
  });
  if (child.error || typeof child.status !== 'number') {
    return launcherError('runtime_unavailable', 69);
  }
  if (child.stdout) process.stdout.write(child.stdout);
  if (child.stderr) process.stderr.write(child.stderr);
  return child.status;
}

module.exports = { launch };
