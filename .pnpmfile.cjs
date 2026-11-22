'use strict';

/**
 * pnpm hook (read automatically by `pnpm install`): keeps compile-time and
 * test-only optional peers out of the dependency graph. pnpm links an
 * optional peer to the project's dev dependency of the same name, and
 * `pnpm install --prod` (Docker image) then installs it as part of the
 * production package:
 * - `@nestjs/swagger` declares `typescript` for its CLI plugin, which this
 *   service does not use (about 24 MB);
 * - `@darmawanweb/ais-its-nest` declares `testcontainers` and
 *   `@nestjs/testing` for its `./testing` helpers: without this hook the
 *   image carries testcontainers, dockerode, ssh2, gRPC and archiver (about
 *   70 MB of test tooling). Tests still resolve both packages, which are
 *   dev dependencies of this repository.
 */
const COMPILE_TIME_PEERS = {
  '@nestjs/swagger': ['typescript'],
  '@darmawanweb/ais-its-nest': ['testcontainers', '@nestjs/testing'],
};

/** `record` without the keys in `names`. */
function without(record, names) {
  if (record === undefined) return undefined;
  return Object.fromEntries(
    Object.entries(record).filter(([name]) => !names.includes(name)),
  );
}

function readPackage(manifest) {
  const peers = COMPILE_TIME_PEERS[manifest.name];
  if (peers === undefined) return manifest;
  return {
    ...manifest,
    peerDependencies: without(manifest.peerDependencies, peers),
    peerDependenciesMeta: without(manifest.peerDependenciesMeta, peers),
  };
}

module.exports = { hooks: { readPackage } };
