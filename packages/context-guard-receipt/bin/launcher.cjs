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
  'python/context_guard_receipt/bootstrap.py',
  'python/context_guard_receipt/canonical.py',
  'python/context_guard_receipt/cli.py',
  'python/context_guard_receipt/contracts.py',
  'python/context_guard_receipt/identity.py',
  'python/context_guard_receipt/protection.py',
  'python/context_guard_receipt/store.py',
  'schemas/capability-record.schema.json',
  'schemas/evidence-boundary.schema.json',
  'schemas/protection-decision.schema.json',
  'schemas/source-identity.schema.json',
  'schemas/store-commit.schema.json',
  'schemas/store-metadata.schema.json',
];
// The installed launcher is part of the caller's/package manager's trust
// boundary. These embedded values prevent a mutable sidecar manifest alone
// from authorizing rewritten payloads; they are not a signature.
const TRUSTED_PAYLOAD_DIGESTS = {
  'LICENSE': 'c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4',
  'NOTICE': '40978c42e96a7b452cb77ef41f28961ca880e46ee7fa7c9589afa4d532655779',
  'README.md': 'cb4eb8bf9c497ee6f493fc7cd7026f6b549498219b8f06572acd8308c3ae3464',
  'bin/context-guard-receipt-mcp.cjs': '883b893d5ee484d63b78174ace60e171dc26e032d05dd19298fb6d6c5229cffd',
  'bin/context-guard-receipt.cjs': 'bdab50b0476e40024ea64f1f6cd0a46260b4707e2297d212bf5034cfd5a87ff8',
  'package.json': 'b585d49acb0d92ca1b3365c2546260b0773a4ed6c969f8557ad6f5dd49f28ecf',
  'python/context_guard_receipt/__init__.py': '1046588c63e24a72c3a57ab0ebd6d60d86c158358b5bbd50ca15cf26322fabc6',
  'python/context_guard_receipt/bootstrap.py': '334787a36bcb7a7441817e33c2dd7641bccac504b83e5117309a69acc87ad211',
  'python/context_guard_receipt/canonical.py': '91b57a1ebf2cc8fa0025ccfc8eaf6f50bc9363e6d3bc05c517b2014bf8a590c7',
  'python/context_guard_receipt/cli.py': '180d998a1942d57c5d92cd3e5451c67674e2f67fc48d4ab9b05af4d49fb1641d',
  'python/context_guard_receipt/contracts.py': '1127a9b90bf2da63a097b066c7f1678109dcf622f40dd6746ef055aa7a98e39e',
  'python/context_guard_receipt/identity.py': 'c02686a71d552473ac1b2b1fc0c3319bd0c246d98379432bb9eaf4a567fca6b5',
  'python/context_guard_receipt/protection.py': '67ae06abb102292b3db09a6731a4aab90b3bc6ceb6dbe836fc636f82f783c347',
  'python/context_guard_receipt/store.py': 'f9e3b168b37a84118c1083f861f11ce66e0fe2260a81d39c82e1f376ab15bbc7',
  'schemas/capability-record.schema.json': '2ad38d92d38effae26182fb698bae7b9e4a9435b0f7b142ac6efff4661bd4131',
  'schemas/evidence-boundary.schema.json': 'b510303bd09adcaf7150415aab5cae3adbe4c99b8482c07a45bb978ad4e82ba7',
  'schemas/protection-decision.schema.json': 'e7cf1b413d286347fda8f0f3a993676212e257f7e280757657032c23b5f9415f',
  'schemas/source-identity.schema.json': 'c20007a9a03e8168feb7b413e035e1d3ef2cdad23a7c404dc25014a03411b047',
  'schemas/store-commit.schema.json': 'e078e14eade2395772936ecd8ec8a9add8b4a71ea45a1b6935645a83a46147ad',
  'schemas/store-metadata.schema.json': '60d36e2b6d07ba9c78b6916183c75d40aa3301dfcd453fcbafdf8e91282dbea7',
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
    encoding: 'utf8',
    maxBuffer: 1024 * 1024,
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
