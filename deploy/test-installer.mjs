import assert from 'node:assert/strict';
import {mkdtempSync,writeFileSync,chmodSync,rmSync,mkdirSync,readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';

const installer=readFileSync('install.sh','utf8'),readme=readFileSync('README.md','utf8');
const version=installer.match(/^VERSION=([0-9.]+)$/m)[1];
assert.ok(readme.includes(`## Current Release: ${version}`),'README release must match installer');
assert.ok(readme.includes(`releases/tag/v${version}`),'README release link must match installer');
assert.ok(readme.includes(createHash('sha256').update(installer).digest('hex')),'README command must verify current installer checksum');
const work=mkdtempSync(join(tmpdir(),'nahan-installer-test-'));
try {
  const bin=join(work,'bin');mkdirSync(bin);
  for(const name of ['ip','ping'])writeFileSync(join(bin,name),'#!/bin/sh\nexit 0\n',{mode:0o700});
  writeFileSync(join(bin,'curl'),`#!/usr/bin/env bash
set -eu
out=
manifest=false
while (($#)); do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    *manifest) manifest=true; shift ;;
    *) shift ;;
  esac
done
if $manifest; then printf '%s' '{"revision":1,"tunnels":[]}' > "$out"
else printf 'tampered binary' > "$out"; fi
`,{mode:0o700});
  const config=join(work,'config.json'),key=join(work,'agent.key');
  const valid={panel:'https://panel.example/api',id:'11111111-1111-4111-8111-111111111111',tokenFile:'/etc/nahan-host-agent/agent.key',stateFile:'/var/lib/nahan-host-agent/state.json'};
  writeFileSync(key,'dummy-test-token-'.repeat(4),{mode:0o600});
  const run=value=>{
    writeFileSync(config,JSON.stringify(value));
    return spawnSync('bash',['install.sh','--check','--config',config,'--key-file',key],{encoding:'utf8',env:{...process.env,PATH:bin+':'+process.env.PATH}});
  };
  for(const panel of ['http://panel.example/api','https://user:pass@panel.example','https://panel.example/?token=secret']) {
    const result=run({...valid,panel});assert.notEqual(result.status,0);assert.match(result.stderr,/Invalid enrollment/);
  }
  chmodSync(key,0o644);
  const permission=run(valid);assert.notEqual(permission.status,0);assert.match(permission.stderr,/chmod 600/);
  chmodSync(key,0o600);
  const tampered=run(valid);assert.notEqual(tampered.status,0);assert.match(tampered.stderr,/checksum mismatch/);
  assert.ok(!tampered.stdout.includes('dummy-test-token'));
  console.log('PASS installer: rejects insecure URLs, exposed key files and tampered binaries without installation');
} finally {rmSync(work,{recursive:true,force:true});}
