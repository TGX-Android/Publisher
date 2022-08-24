/*
 * This file is a part of Telegram X Publisher
 * Copyright © Vyacheslav Krylov (slavone@protonmail.ch) 2022
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

'use strict';

process.env.NTBA_FIX_319 = 1;
process.env.NTBA_FIX_350 = 1;

const fs = require('fs'),
      os = require('os'),
      level = require('level'),
      crypto = require('crypto'),
      TelegramBot = require('node-telegram-bot-api'),
      path = require('path'),
      https = require('https'),
      http = require('http'),
      iconv = require('iconv-lite');
const { spawn, exec, execSync } = require('child_process');
const { google } = require('googleapis');

// ERROR

function globalErrorHandler () {
  const stack = new Error('Global error happened here:').stack;
  return (error) => {
    console.log(error.code, stack, error);
  };
}

// ARGV CONSTANTS

function checkPath (path) {
  return path && fs.existsSync(path);
}

const LOCAL = process.env.TGX_PRODUCTION !== '1';
const settings = JSON.parse(fs.readFileSync(path.join(__dirname, 'settings.json'), 'UTF-8'));
if (!settings.app.id || !settings.app.id.match(/^(?!\.)[a-z0-9._]+(?!\.)$/))
  throw Error('app.id is not specified in settings.json or not valid: ' + settings.app.id);

const TESTING_URL = settings.url.testing;
const MARKET_URL = settings.url.market;

const ADMIN_USER_ID = settings.telegram.admin_user_id;
const BETA_CHAT_ID = settings.telegram.target_chat_id.public_builds;
const PR_CHAT_ID = settings.telegram.target_chat_id.pr_builds;
const ALPHA_CHAT_ID = LOCAL ? ADMIN_USER_ID : settings.telegram.target_chat_id.private_builds;
const INTERNAL_CHAT_ID = settings.telegram.target_chat_id.internal_builds;

const TELEGRAM_API_TOKEN_2 = settings.tokens.verifier.production;

const TELEGRAM_APP_ID = process.env.TELEGRAM_APP_ID || settings.telegram.server.api_id;
const TELEGRAM_APP_HASH = process.env.TELEGRAM_APP_HASH || settings.telegram.server.api_hash;

const PACKAGE_NAME = settings.app.id;

['TGX_SOURCE_PATH', 'TGX_KEYSTORE_PATH', 'ANDROID_SDK_ROOT', 'GOOGLE_TOKEN_PATH'].forEach((path) => {
  if (!checkPath(process.env[path]) && !(LOCAL && path === 'GOOGLE_TOKEN_PATH')) {
    console.error(path + ' not found! ' + process.env[path]);
    process.exit(1);
    return;
  }
  settings[path] = process.env[path];
});

// TELEGRAM CONSTANTS

const APK_MIME_TYPE = 'application/vnd.android.package-archive';
const ZIP_MIME_TYPE = 'application/octet-stream'; //'application/zip';
const TXT_MIME_TYPE = 'application/octet-stream'; // 'text/plain';

const TELEGRAM_API_TOKEN = process.env.TELEGRAM_API_TOKEN || settings.tokens.builder[LOCAL ? 'debug' : 'production'];
if (!TELEGRAM_API_TOKEN) {
  console.error('Invalid TELEGRAM_API_TOKEN', TELEGRAM_API_TOKEN);
  process.exit(1);
  return;
}

if (!TELEGRAM_APP_ID || !TELEGRAM_APP_HASH) {
  console.error('Invalid Telegram APP_ID / APP_HASH', TELEGRAM_APP_ID, TELEGRAM_APP_HASH);
  process.exit(1);
  return;
}

// GOOGLE PLAY CONSTANTS

const googleAuth = LOCAL ? null : new google.auth.GoogleAuth({
  keyFile: settings.GOOGLE_TOKEN_PATH,
  scopes: ['https://www.googleapis.com/auth/androidpublisher'],
});
if (!LOCAL) {
  google.options({
    // timeout: 1000,
    auth: googleAuth
  });
}
const play = LOCAL ? null : google.androidpublisher({
  version: 'v3',
  params: {
    packageName: PACKAGE_NAME
  }
});

// MAIN


const db = level('./db');

const cpus = os.cpus();
const cpuCount = cpus.length;
let threadCount;
const cpuNames = [];
cpus.forEach((cpu) => {
  if (!cpuNames.includes(cpu.model)) {
    cpuNames.push(cpu.model);
  }
});
const platform = os.platform();
if (platform === 'linux') {
  const output = execSync('lscpu -p | grep -Evc \'^#\'', {encoding: 'utf8'});
  threadCount = parseInt(output.trim());
} else if (platform === 'darwin') {
  const output = execSync('sysctl -n hw.logicalcpu_max', {encoding: 'utf8'});
  threadCount = parseInt(output.trim());
}
let cpuSignature = cpuNames.join(', ') + ' @ ' + cpuCount + (cpuCount > 1 ? ' cores' : ' core') + (threadCount !== cpuCount ? ' (' + threadCount + ' threads)' : '');

const cur = {
  cache: {},
  build_no: -1,
  pending_build: null,
  uploaded_version: -1,
  killServer: false,
  server: null
};

function runServer (onClose, detached) {
  detached = !!detached;
  const server = spawn('telegram-bot-api',
    [
      '--api-id=' + TELEGRAM_APP_ID,
      '--api-hash=' + TELEGRAM_APP_HASH,
      '--local',
      '--dir=' + process.cwd() + '/server',
      '--log=' + process.cwd() + '/server.log',
      '--verbosity=' + (settings.server_verbosity || 1)
    ],
    {detached}
  );
  server.stdout.on('data', (data) => {
    if (LOCAL) {
      console.log('Server says:', data);
    }
  });
  server.stderr.on('data', (data) => {
    if (LOCAL) {
      console.log('Server cries:', data);
    }
  });
  server.on('close', (code) => {
    console.log(`Server process exited with code ${code}`);
    if (onClose) {
      onClose(server);
    }
  });
  if (detached) {
    server.unref();
  }
  return server;
}

cur.server = runServer((closedServer) => {
  if (cur.server === closedServer) {
    console.error('Server closed, quitting process', cur.exiting);
    cur.server = null;
    if (!cur.exiting) {
      process.kill(process.pid, 'SIGINT');
    }
  } else {
    console.error('Unknown server closed');
  }
});

function isOffline () {
  return cur.server === null;
}

async function stopServer () {
  console.log('Killing server…', isOffline());
  if (!isOffline()) {
    cur.server.kill('SIGTERM');
  }
}

// Wait for the server
Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 1000);

const TELEGRAM_API_URL = 'http://127.0.0.1:8081';

const bots = [
  {
    id: 'private',
    bot: new TelegramBot(TELEGRAM_API_TOKEN, {
      polling: true,
      filepath: false,
      baseApiUrl: TELEGRAM_API_URL
    })
  },
  {
    id: 'public',
    bot: new TelegramBot(TELEGRAM_API_TOKEN_2, {
      polling: true,
      filepath: false,
      baseApiUrl: TELEGRAM_API_URL
    })
  }
];
const botMap = {};
bots.forEach((bot) => {
  botMap[bot.id] = bot.bot;
});

function nextBuildId () {
  let id = cur.build_no ? cur.build_no + 1 : 1;
  cur.build_no = id;
  db.put('build_count', id);
  return id;
}

function areEqual (a, b) {
  if (a === b)
    return true;
  if (!a || !b)
    return false;
  for (let key in a) {
    if (a[key] === b[key] || (typeof a[key] === typeof b[key] && typeof a[key] === 'object' && areEqual(a[key], b[key])))
      continue;
    return false;
  }
  for (let key in b) {
    if (!a.hasOwnProperty(key))
      return false;
  }
  return true;
}

function ucfirst (str) {
  return str && str.length ? str.charAt(0).toUpperCase() + str.substring(1) : str;
}

function escapeRegExp (string) {
  return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function empty (obj) {
  if (typeof obj === 'object') {
    for (const key in obj) {
      if (obj.hasOwnProperty(key)) {
        return false;
      }
    }
  }
  return true;
}

async function getObject (type, id) {
  if (!cur.cache[type]) {
    cur.cache[type] = {};
  }
  const cached = cur.cache[type][id];
  if (cached !== undefined) {
    return cached;
  }
  try {
    const value = await db.get(type + '_' + id, {valueEncoding: 'json'});
    cur.cache[type][id] = value;
    return value;
  } catch (err) {
    cur.cache[type][id] = null;
    return null;
  }
}

function checksum (path, callback, algorithm) {
  const stream = fs.createReadStream(path);
  const checksum = crypto.createHash(algorithm);
  stream.on('error', function (err) {
    return callback(err, null)
  });
  stream.on('data', function (chunk) {
    try {
      checksum.update(chunk)
    } catch (ex) {
      return callback(ex, null)
    }
  });
  stream.on('end', function () {
    return callback(null, checksum.digest('hex'))
  });
}

async function storeObject (type, obj, id) {
  if (obj === undefined)
    return;
  if (id === undefined)
    id = obj.id;
  if (id === undefined)
    return;
  const existing = await getObject(type, id);
  if (!areEqual(obj, existing)) {
    cur.cache[type][id] = obj;
    await db.put(type + '_' + id, obj, {valueEncoding: 'json'});
  }
}

function getCommitDate (callback) {
  exec('git show -s --format=%ct', {cwd: settings.TGX_SOURCE_PATH}, (error, stdout, stderr) => {
    if (error) {
      throw error;
    }
    const result = parseInt(trimIndent(stdout).trim());
    callback(result);
  });
}

function gitPull (callback) {
  exec('git pull', {cwd: settings.TGX_SOURCE_PATH}, (error, stdout, stderr) => {
    if (error) {
      throw error;
    }
    callback(stdout);
  });
}

function getGitData (callback) {
  exec('echo "$(git rev-parse --short HEAD) $(git rev-parse HEAD) $(git show -s --format=%ct) $(git config --get remote.origin.url) $(git rev-parse --abbrev-ref HEAD) $(git log -1 --pretty=format:\'%an\')"', {cwd: settings.TGX_SOURCE_PATH}, (error, stdout, stderr) => {
    if (error) {
      throw error;
    }
    const result = trimIndent(stdout).trim().split(' ', 6);
    let remoteUrl = result[3];
    if (remoteUrl.startsWith('git@')) {
      let index = remoteUrl.indexOf(':', 4);
      let domain = remoteUrl.substring(4, index);
      let endIndex = remoteUrl.endsWith('.git') ? remoteUrl.length - 4 : remoteUrl.length;
      remoteUrl = 'https://' + domain + '/' + remoteUrl.substring(index + 1, endIndex);
    }
    callback({
      commit: {
        short: result[0],
        long: result[1]
      },
      remoteUrl: remoteUrl,
      branch: result[4],
      author: result[5],
      date: parseInt(result[2])
    });
  });
}

function getLocalChanges (callback) {
  exec('git status --porcelain --untracked-files=no', {cwd: settings.TGX_SOURCE_PATH}, (error, stdout, stderr) => {
    if (error) {
      throw error;
    }
    const changes = trimIndent(stdout).trim();
    callback(changes && changes.length ? changes : null);
  });
}

function fetchHttp (url, needBinary, httpOptions) {
  return new Promise((accept, reject) => {
    const parsed = new URL(url);
    const protocol = (parsed.protocol === 'https:' ? https : http);
    try {
      protocol.get(Object.assign({
        host: parsed.host,
        path: parsed.pathname + parsed.search
      }, httpOptions || {}), (res) => {
        toUtf8(res, (contentType, content) => {
          accept({statusCode: res.statusCode, statusMessage: res.statusMessage, content, contentType});
        }, needBinary);
      }).on('error', reject);
    } catch (e) {
      console.error('Cannot fetch', url, e);
      reject(e);
    }
  });
}

function toUtf8 (res, onDone, needBinary) {
  const contentType = (res.headers['content-type'] || '').split(';');
  let encoding = null;
  for (let i = 0; i < contentType.length; i++) {
    const keyValue = contentType[i].split('=');
    if (keyValue.length === 2 && keyValue[0].toLowerCase() === 'charset') {
      encoding = keyValue[1].toLowerCase();
    }
  }
  let data = [];
  res.setEncoding('binary');
  res.on('data', (chunk) => {
    data.push(Buffer.from(chunk, 'binary'));
  });
  res.on('end', () => {
    const binary = Buffer.concat(data);
    if (needBinary) {
      onDone(contentType, binary);
    } else {
      if (encoding && encoding !== 'utf-8') {
        onDone(contentType, iconv.encode(iconv.decode(binary, encoding), 'utf-8'));
      } else {
        onDone(contentType, binary.toString('utf-8'));
      }
    }
  });
}

function getProperty (data, variableName) {
  variableName = variableName.replace(/\./gi, '\\.');
  const regexp = new RegExp(variableName + '\s*=\s*[^\n]+');
  const lookup = data.match(regexp);
  const result = lookup && lookup.length == 1 ? lookup[0] : null;
  if (result) {
    return result.substring(result.indexOf('=') + 1)
  }
  return null;
}

function monthYears (now, then) {
  let years = now.getUTCFullYear() - then.getUTCFullYear()
  let months = 0;
  if (now.getUTCMonth() < then.getUTCMonth() ||
    (now.getUTCMonth() === then.getUTCMonth() && now.getUTCDate() < then.getUTCDate())) {
    years--
    months = 12 - then.getUTCMonth() + now.getUTCMonth()
  } else {
    months = now.getUTCMonth() - then.getUTCMonth()
  }
  if (now.getUTCDate() < then.getUTCDate()) {
    months--
  }
  return years + '.' + months;
} 

function getAppVersion (callback) {
  fs.readFile(settings.TGX_SOURCE_PATH + '/version.properties', 'utf-8', function (err, data) {
    if (err) {
      callback(null);
    } else {
      const buildVersion = parseInt(getProperty(data, 'version.app'));
      const creationDate = parseInt(getProperty(data, 'version.creation'));
      if (!creationDate) {
        callback('#' + buildVersion);
        return;
      }
      const majorVersion = getProperty(data, 'version.major');
      getCommitDate((commitDate) => {
        const buildDate = new Date(commitDate * 1000);
        const fromDate = new Date(creationDate);
        const minorVersion = monthYears(buildDate, fromDate);
        callback({code: buildVersion, name: majorVersion + '.' + minorVersion + '.' + buildVersion});
      });
    }    
  });
}

function escapeMarkdown (text) {
  if (!text)
    return text;
  return text.replace(/\\/g, '\\\\').replace(/\-/g, '\\-').replace(/\*/g, '\\*').replace(/\./g, '\\.').replace(/\!/g, '\\!');
}

function escapeHtml (text) {
  if (!text)
    return text;
  return text.replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function trimIndent (text) {
  if (!text)
    return text;
  const lines = text.split('\n');
  let minIndendWidth = -1;
  for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
    const line = lines[lineIndex];
    if (line.length) {
      let indentWidth = 0;
      for (let i = 0; i < line.length; i++) {
        if (line[i] === ' ') {
          indentWidth++;
        } else {
          break;
        }
      }
      minIndendWidth = minIndendWidth === -1 || minIndendWidth > indentWidth ? indentWidth : minIndendWidth;
      if (indentWidth === 0)
        break;
    }
  }
  if (minIndendWidth <= 0) {
    return text;
  }
  let result = '';
  for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
    const line = lines[lineIndex];
    if (lineIndex > 0)
      result += '\n';
    if (line.length) {
      result += line.substring(minIndendWidth);
    }
  }
  return result;
}

function duration (start, end, full) {
  const time = end - start;
  if (time === 0) {
    return full ? 'instant' : '0s';
  }
  if (time < 1000) {
    return time + (full ? time === 1 ? ' millisecond' : ' milliseconds' : 'ms');
  }
  const totalSeconds = time / 1000;
  const totalMinutes = Math.floor(totalSeconds / 60);

  let seconds = (time - totalMinutes * 60000) / 1000;

  let result = '';
  if (totalMinutes !== 0) {
    if (result.length) result += ' ';
    result += totalMinutes + (full ? totalMinutes !== 1 ? ' minutes' : ' minute' : 'm');
  }
  if (seconds !== 0) {
    if (result.length) result += ' ';
    result += (seconds % 1 !== 0 ? seconds.toFixed(1) : seconds) + (full ? seconds !== 1 ? ' seconds' : ' second' : 's');
  }

  return result;
}

async function traceMaxApkVersionCode (type, versionCode, uploadDate) {
  const cur = await getObject('apk', type);
  const max = await getObject('apk', 'max');
  if (!max || versionCode > max.versionCode) {
    await storeObject('apk', {versionCode: versionCode, uploadDate: uploadDate}, 'max');
  }
  if (!cur || versionCode > cur.versionCode) {
    await storeObject('apk', {versionCode: versionCode, uploadDate: uploadDate}, type);
  }
}

async function canUploadApk (type, versionCode) {
  const cur = await getObject('apk', type);
  const max = type === 'universal' ? await getObject('apk', 'max') : null;
  return versionCode > Math.max(cur ? cur.versionCode : 0, max ? max.versionCode : 0);
}

async function traceDuration (type, name, startTime, endTime, isComplete) {
  if (typeof endTime !== 'number')
    endTime = endTime.getTime();
  if (typeof startTime !== 'number')
    startTime = startTime.getTime();
  if (!isComplete) {
    type += '_failed';
  }
  let value = await getObject(type, name);
  if (!value) {
    value = {
      total: 0,
      items: []
    };
  }
  value.total += (endTime - startTime);
  value.items.push([startTime, endTime]);
  await storeObject(type, value, name);
}

function main () {
  db.get('build_count', (err, value) => {
    cur.build_no = err ? 0 : parseInt(value);
  });
  db.get('uploaded_version', (err, value) => {
    cur.uploaded_version = err ? 0 : parseInt(value);
  });
}

async function estimateBuildDuration (build) {
  let haveMissing = false;
  let totalEstimate = 0;
  for (let i = 0; i < build.tasks.length; i++) {
    const task = build.tasks[i];
    const stat = await getObject('task_stat', task.name);
    if (stat && stat.total) {
      task.estimateDuration = stat.total / stat.items.length;
      totalEstimate += task.estimateDuration;
    } else {
      haveMissing = true;
    }
  }
  if (!haveMissing) {
    build.estimateDuration = totalEstimate;
  }
}

async function killTask (task) {
  setTimeout(async () => {
    if (!task.processTerminated && task.process) {
      await task.process.kill('SIGKILL');
      task.processTerminated = true;
    }
  }, 2500);
  if (task.process) {
    await task.process.kill();
    task.processTerminated = true;
  }
}

function findFile (dir, regexp, callback) {
  fs.readdir(dir, {withFileTypes: true}, (err, files) => {
    if (err) {
      console.error('Cannot lookup for file', dir);
      callback(null);
    } else {
      for (let i = 0; i < files.length; i++) {
        const fileName = files[i].name;
        let match = fileName.match(regexp);
        if (match && match.length) {
          if (match[0].length === fileName.length) {
            callback(fileName);
            return;
          }
        }
      }
      console.error('None of the files match regexp!', regexp, JSON.stringify(files));
      callback(null);
    }
  });
}

function toDisplayAlgorithm (algorithm) {
  switch (algorithm) {
    case 'md5': return 'MD5';
    case 'sha1': return 'SHA-1';
    case 'sha256': return 'SHA-256';
    default: return algorithm;
  }
}

function getDisplayVariant (variant) {
  switch (variant) {
    case 'arm64': return 'arm64-v8a';
    case 'arm32': return 'armeabi-v7a';
    default: return variant;
  }
}

function getBuildFiles (build, variant, callback) {
  const architecture = getDisplayVariant(variant); // == 'universal' ? null : getDisplayVariant(variant);
  
  const outputsDir = settings.TGX_SOURCE_PATH + '/app/build/outputs';

  const mappingDir = outputsDir + '/mapping/' + variant + 'Release';
  const apkDir = outputsDir + '/apk/' + variant + '/release';

  const nativeDebugSymbolsFile = outputsDir + '/native-debug-symbols/' + variant + 'Release' + '/native-debug-symbols.zip';

  const result = { };

  const check = () => {
    if (result.nativeDebugSymbolsFile !== undefined && result.apkFile !== undefined && (result.apkFile === null || (result.apkFile.checksum && result.apkFile.checksum.md5 !== undefined && result.apkFile.checksum.sha1 !== undefined && result.apkFile.checksum.sha256 !== undefined)) && result.mappingFile !== undefined && result.metadata !== undefined) {
      if (result.nativeDebugSymbolsFile && result.apkFile && (result.apkFile.checksum && result.apkFile.checksum.sha256 && result.apkFile.checksum.sha1 && result.apkFile.checksum.md5) && (result.mappingFile || build.outputApplication.dontObfuscate) && result.metadata) {
        callback(result);
      } else {
        console.error('Cannot find build files for #' + build.version.name, JSON.stringify(result));
        callback(null);
      }
    }
  };

  const prefix = '^' + escapeRegExp(build.outputApplication.name || 'Telegram X').replace(/ /g, '-').replace(/#/g, '') + '-' + build.version.name.replace(/\./gi, '\\.') + '(?:\\+[0-9,]+)?' + (architecture ? '(?:-' + architecture + ')?' : '') ;
  fs.exists(nativeDebugSymbolsFile, (exists) => {
    result.nativeDebugSymbolsFile = exists ? {path: nativeDebugSymbolsFile} : null;
    check();
  });
  findFile(apkDir, RegExp(prefix + '\\.apk$'), (apkFile) => {
    if (apkFile) {
      result.apkFile = {path: apkDir + '/' + apkFile};
      ['sha256', 'sha1', 'md5'].forEach((algorithm) => {
        checksum(result.apkFile.path, (err, checksum) => {
          if (!result.apkFile.checksum) {
            result.apkFile.checksum = {};
          }
          result.apkFile.checksum[algorithm] = checksum ? checksum : null;
          check();
        }, algorithm);
      });
    } else {
      result.apkFile = null;
      check();
    }
  });
  findFile(apkDir, RegExp('^output-metadata\\.json$'), (metadataFile) => {
    if (metadataFile) {
      fs.readFile(apkDir + '/' + metadataFile, 'utf-8', (err, data) => {
        const metadata = err ? null : JSON.parse(data);
        if (err || !(metadata &&
            metadata.elements &&
            metadata.elements.length == 1 &&
            metadata.elements[0].versionCode)) {
          console.error('Cannot read metadata file', err, data);
          result.metadata = null;
          check();
        } else {
          result.metadata = metadata.elements[0];
          check();
        }
      });
    } else {
      result.metadata = null;
      check();
    }
  });
  findFile(mappingDir, RegExp(prefix + '\\.txt$'), (mappingFile) => {
    result.mappingFile = mappingFile ? {path: mappingDir + '/' + mappingFile} : null;
    check();
  });
}

function getFromToCommit (build) {
  if (build.outputApplication && build.outputApplication.isPRBuild)
    return null;
  if (build.googlePlayTrack) {
    if (build.previousGooglePlayBuild &&
        build.previousGooglePlayBuild.remoteUrl === build.git.remoteUrl) {
      return {
        commit_range: build.previousGooglePlayBuild.commit.short + '...' + build.git.commit.short,
        from_version: build.previousGooglePlayBuild.version.code
      };
    }
  } else if (build.telegramTrack) {
    if (build.previousTelegramBuild &&
        build.previousTelegramBuild.remoteUrl === build.git.remoteUrl) {
      return {
        commit_range: build.previousTelegramBuild.commit.short + '...' + build.git.commit.short,
        from_version: build.previousTelegramBuild.version.code
      };
    }
  }
  return null;
}

function getBuildCaption (build, variant, isPrivate) {
  let caption = '<b>Version</b>: <code>' + build.version.name + '-' + getDisplayVariant(variant) + '</code>';
  caption += '\n<b>Commit</b>: <a href="' + build.git.remoteUrl + '/tree/' + build.git.commit.long + '">' + build.git.commit.short + '</a>';
  if (build.git.date) {
    caption += ', ' + toDisplayDate(build.git.date);
  }
  if (build.pullRequestsMetadata || !empty(build.pullRequests)) {
    caption += '\n<b>Pull requests</b>: ' + toDisplayPullRequestList(build);
  }
  caption += '\n';
  const checksums = ['md5', 'sha1', 'sha256'];
  checksums.forEach((checksum) => {
    const hash = build.files[variant].apkFile.checksum[checksum];
    caption += '\n<b>' + toDisplayAlgorithm(checksum) + '</b>: <a href="https://t.me/tgx_bot?start=' + hash + '">' + hash + '</a>';
  });

  const fromToCommit = getFromToCommit(build);
  if (fromToCommit) {
    caption += '\n\n<b>Changes from ' + fromToCommit.from_version + '</b>: <a href="' + build.git.remoteUrl + '/compare/' + fromToCommit.commit_range + '">' + fromToCommit.commit_range + '</a>';
  }

  caption += '\n\n#' + variant;
  switch (build.googlePlayTrack) {
    case 'production': caption += ' #stable'; break;
    case 'beta': caption += ' #beta'; break;
    case 'alpha': caption += ' #alpha'; break;
  }
  caption += ' #apk';
  return caption;
}

function publishToTelegram (bot, task, build, onDone, chatId, onlyPrivate, disableNotification) {
  const docs = [];
  const variants = [];
  for (let variant in build.files) {
    const file_id = build.files[variant].apkFile.remote_id;
    if (file_id) {
      const doc = {
        type: 'document',
        media: file_id,
        caption: getBuildCaption(build, variant, false),
        parse_mode: 'HTML'
      };
      let ok = variant !== 'universal' || build.variants.length === 1;
      if (onlyPrivate) {
        ok = !ok;
      }
      if (ok) {
        docs.push(doc);
        variants.push(variant);
      }
    } else {
      console.log('Some of docs do not have file_id available!');
      onDone(1);
      return;
    }
  }
  if (docs.length > 1) {
    bot.sendMediaGroup(chatId, docs, {
      disable_notification: disableNotification
    }).then((messages) => {
      if (!build.publicMessages) {
        build.publicMessages = [];
      }
      for (let i = 0; i < messages.length; i++) {
        const messageId = messages[i].message_id;
        build.publicMessages.push({
          variant: variants[i],
          message_id: messageId,
          url: messages[i].sender_chat && messages[i].sender_chat.username ? 
            'https://t.me/' + messages[i].sender_chat.username + '/' + messageId :
            null
        });
      }
      if (!onlyPrivate) {
        tracePublishedTelegramBuild(build).then(() => {
          onDone(0);
        });
      } else {
        onDone(0);
      }
    }).catch((error) => {
      onDone(1);
      globalErrorHandler()(error);
    });
  } else if (docs.length === 1) {
    bot.sendDocument(chatId, docs[0].media, {
      caption: docs[0].caption,
      parse_mode: docs[0].parse_mode,
      disable_notification: disableNotification
    }).then((message) => {
      if (!build.publicMessages) {
        build.publicMessages = [];
      }
      build.publicMessages.push({
        variant: variants[0],
        message_id: message.message_id,
        url: message.sender_chat && message.sender_chat.username ?
          'https://t.me/' + message.sender_chat.username + '/' + message.message_id :
          null
      });
      if (!onlyPrivate) {
        tracePublishedTelegramBuild(build).then(() => {
          onDone(0);
        });
      } else {
        onDone(0);
      }
    }).catch((error) => {
      onDone(1);
      globalErrorHandler()(error);
    });
  } else {
    onDone(0);
  }
}

function uploadToTelegram (bot, task, build, variant, onDone) {
  const files = build.files[variant];
  if (!files) {
    console.log('Build files not found for variant', variant);
    onDone(1);
    return;
  }

  const failWithError = (message, e) => {
    if (!task.endTime) {
      console.error(message, e);
      onDone(1);
    }
  };

  bot.sendDocument(build.serviceChatId, fs.createReadStream(files.apkFile.path), {
      reply_to_message_id: build.serviceMessageId,
      caption: getBuildCaption(build, variant),
      parse_mode: 'HTML'
    }, {
      contentType: APK_MIME_TYPE
    }).then((message) => {
    files.apkFile.remote_id = message.document.file_id;
    bot.sendDocument(build.serviceChatId, fs.createReadStream(files.nativeDebugSymbolsFile.path), {
      reply_to_message_id: message.message_id
    }, {
      contentType: 'application/zip'
    }).then((symbolsMessage) => {
      if (!files.mappingFile) { // Mapping file doesn't exist for builds made with --dontobfuscate option
        onDone(0);
        return;
      }
      bot.sendDocument(build.serviceChatId, fs.createReadStream(files.mappingFile.path), {
        reply_to_message_id: message.message_id
      }, {
        contentType: 'text/plain'
      }).then((mappingMessage) => {
        onDone(0);
      }).catch((e) => {
        failWithError('Cannot upload mapping file', e);
      })
    }).catch((e) => {
      failWithError('Cannot upload native-debug-symbols.zip', e);
    });
  }).catch((e) => {
    failWithError('Cannot upload telegram file', e);
  });

  return async () => {
    if (!task.endTime) {
      failWithError('Aborted', new Error());
    }
  };
}

function traceBuiltApk (build, task, variant, checksum, onDone) {
  for (let algorithm in checksum) {
    const hash = checksum[algorithm];
    const data = toShotBuildInfo(build);
    Object.assign(data, {
      variant: variant,
      hashAlgorithm: algorithm
    });
    if (build.googlePlayTrack) {
      data.googlePlayTrack = build.googlePlayTrack;
    }
    if (build.telegramTrack) {
      data.telegramTrack = build.telegramTrack;
    }
    db.put('hash_' + hash, data, {valueEncoding: 'json'});
  }
}

function findApkByHash (hash, callback) {
  db.get('hash_' + hash, {valueEncoding: 'json'}, callback);
}

function toShotBuildInfo (build) {
  const buildData = {
    version: build.version
  };
  Object.assign(buildData, build.git);
  if (!empty(build.pullRequests)) {
    buildData.pullRequests = build.pullRequests;
  }
  return buildData;
}

async function tracePublishedTelegramBuild (build) {
  await storeObject('telegram', toShotBuildInfo(build), build.telegramTrack);
}

async function findPublishedTelegramBuild (build) {
  if (build.telegramTrack) {
    return await getObject('telegram', build.telegramTrack);
  }
  return null;
}

async function tracePublishedGooglePlayBuild (build) {
  await storeObject('google_play', toShotBuildInfo(build), build.googlePlayTrack);
}

async function findPublishedGooglePlayBuild (build) {
  if (build.googlePlayTrack) {
    return await getObject('google_play', build.googlePlayTrack);
  }
  return null;
}

function uploadToGooglePlay (task, build, onDone) {
  if (LOCAL || !build.files || !build.variants || !build.googlePlayTrack) {
    onDone(1);
    return;
  }

  let variantsToCheck = build.variants.length;
  let onVariantChecked = () => {
    if (--variantsToCheck !== 0 || task.endTime)
      return;

    // at this point we are sure that no apks were uploaded yet

    play.edits.insert().then((appEdit) => {
      console.log('Created an AppEdit', JSON.stringify(appEdit));
      const editId = appEdit.data.id;

      let remainingApkCount = build.variants.length;
      const uploadedVersionCodes = [];
      let onBuildUploaded = (uploadedBuildVariant) => {
        if (--remainingApkCount !== 0)
          return;
        // Setting track
        play.edits.tracks.update({
          editId: editId,
          track: build.googlePlayTrack,
          // changesNotSentForReview: true,
          requestBody: {
            track: build.googlePlayTrack,
            releases: [{
              name: build.version.name + ' ' + build.googlePlayTrack,
              status: build.googlePlayTrack === 'production' ? 'draft' : 'completed',
              releaseNotes: [
                {
                  language: 'en-US',
                  text: build.version.name + (
                    build.googlePlayTrack !== 'production' ?
                    ' ' + build.googlePlayTrack :
                    ''
                  ) + '\n\n' + 'https://t.me/tgx_android'
                }
              ],
              versionCodes: uploadedVersionCodes
            }]
          }
        }).then((updatedTrack) => {
          console.log('Successfully updated track', JSON.stringify(updatedTrack));
          play.edits.commit({
            editId: editId
          }).then((appEdit) => {
            console.log('Successfully commited google play changes', JSON.stringify(appEdit));
            tracePublishedGooglePlayBuild(build).then(() => {
              onDone(0);
            });
          }).catch((e) => {
            console.error('Failed to commit changes to google play', build.googlePlayTrack, e);
            onDone(1);
          });
        }).catch((updatedTrackError) => {
          console.error('Failed to update track', build.googlePlayTrack, updatedTrackError);
          onDone(1);
        });
      };
      for (let i = 0; i < build.variants.length; i++) {
        const variant = build.variants[i];
        if (build.variants.length > 1 && variant === 'universal') {
          onBuildUploaded(variant);
          continue;
        }
        const files = build.files[variant];
        const apkStream = fs.createReadStream(files.apkFile.path);

        play.edits.apks.upload({
          editId: editId,
          media: {
            mimeType: APK_MIME_TYPE,
            body: apkStream
          }
        }).then((uploadedApk) => {
          console.log('Successfully uploaded APK', JSON.stringify(uploadedApk));
          traceMaxApkVersionCode(variant, uploadedApk.data.versionCode, new Date());
          if (uploadedApk.data.binary.sha256 !== files.apkFile.checksum.sha256) {
            console.error('SHA-256 mismatch!', variant);
            task.logPublicly('SHA-256 mismatch!');
            onDone(1);
            return;
          }
          uploadedVersionCodes.push(uploadedApk.data.versionCode);
          const nativeStream = fs.createReadStream(files.nativeDebugSymbolsFile.path);
          play.edits.deobfuscationfiles.upload({
            editId: editId,
            deobfuscationFileType: 'nativeCode',
            apkVersionCode: uploadedApk.data.versionCode,
            media: {
              mimeType: ZIP_MIME_TYPE,
              body: nativeStream
            }
          }).then((uploadedNativeDebugSymbols) => {
            nativeStream.close();
            console.log('native-debug-symbols.zip uploaded', variant, JSON.stringify(uploadedNativeDebugSymbols));
            const mappingStream = fs.createReadStream(files.mappingFile.path);
            play.edits.deobfuscationfiles.upload({
              editId: editId,
              deobfuscationFileType: 'proguard',
              apkVersionCode: uploadedApk.data.versionCode,
              media: {
                mimeType: TXT_MIME_TYPE,
                body: mappingStream
              }
            }).then((uploadedMappingFile) => {
              mappingStream.close();
              console.log('Mapping file uploaded', variant, JSON.stringify(uploadedMappingFile));
              // Success! Now we can proceed.
              onBuildUploaded(variant);
            }).catch((mappingFileUploadError) => {
              console.error('Failed to upload mapping file.', variant, mappingFileUploadError);
              onDone(1);
            });
          }).catch((nativeDebugSymbolsUploadError) => {
            console.error('Failed to upload native-debug-symbols.zip', variant, nativeDebugSymbolsUploadError);
            onDone(1);
          });
        }).catch((apkUploadError) => {
          console.error('Failed to upload apk', variant, apkUploadError);
          onDone(1);
        });

        /*media: {
          mimeType: ,
          body: apk
        }*/
      }
    }).catch((appEditError) => {
      console.error('Failed to create AppEdit', appEditError);
      onDone(1);
    });
  };

  for (let i = 0; i < build.variants.length; i++) {
    const variant = build.variants[i];
    if (!build.files[variant]) {
      console.error('Passed variant is not built', variant);
      onDone(1);
      return;
    }
    const files = build.files[variant];
    if (files.metadata.versionCode < cur.maximumApkVersionCode) {
      console.error('Version code is lower than maximum', variant, files.metadata.versionCode, cur.maximumApkVersionCode);
      onDone(1);
      return;
    }
    canUploadApk(variant, files.metadata.versionCode).then((success) => {
      if (success) {
        onVariantChecked();
      } else {
        const msg = 'APK #' + build.version.name + ' was already published. Version bump required.';
        trask.logPublicly(msg);
        console.error(msg);
        onDone(1);
      }
    });
  }

  return async () => {
    if (!task.endTime) {
      // TODO abort upload somehow??

      onDone(1);
    }
  };
}

main();

function sendArray (bot, chatId, array, parseMode, delimiter) {
  if (!array || !array.length) {
    bot.sendMessage(chatId, '<b>Nothing found!</b>', {parse_mode: 'HTML'}).catch(globalErrorHandler());
    return;
  }
  if (!delimiter) {
    delimiter = '\n';
  }
  let remaining = array.length;
  let text = '';
  while (remaining > 0) {
    const item = array[array.length - remaining];
    if (text.length + item.length + (text.length ? delimiter.length : 0) > 4000) {
      bot.sendMessage(chatId, text, {parse_mode: parseMode}).catch(globalErrorHandler());
      text = item;
    } else {
      if (text.length) {
        text += delimiter;
      }
      text += item;
    }
    remaining--;
    if (remaining == 0) {
      bot.sendMessage(chatId, text, {parse_mode: parseMode}).catch(globalErrorHandler());
    }
  }
}

function sleep (milliseconds) {
  return new Promise(resolve => setTimeout(resolve, milliseconds))
}

function toDisplayDate (seconds) {
  return new Date(seconds * 1000).toLocaleString('en-GB', {
    day: 'numeric',
    month: 'numeric',
    year: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
    timeZoneName: 'short',
    timeZone: 'UTC'
  });
}

function toDisplayPullRequestList (build) {
  const remoteUrl = build.remoteUrl || (build.git ? build.git.remoteUrl : '');
  const toItem = (pullRequestId, pullRequestCommit, pullRequest, nextPullRequest) => {
    const pullRequestUrl = remoteUrl + '/pull/' + pullRequestId;
    let text = '<a href="' + pullRequestUrl + '"><b>' + pullRequestId + '</b></a>';
    if (pullRequest) {
      text += ' / <a href="' + pullRequestUrl + '/files/' + pullRequest.commit.long + '">' + pullRequest.commit.short + '</a>';
      if (pullRequest.github) {
        if (Math.max(pullRequest.github.additions || pullRequest.github.deletions) > 0) {
          text += ' (<code>' + [pullRequest.github.additions, -pullRequest.github.deletions].filter((item) => item !== 0).map((item) => item > 0 ? '+' + item : item.toString()) + '</code>)'
        }
        if (!nextPullRequest || !nextPullRequest.github || nextPullRequest.github.name !== pullRequest.github.name) {
          text += ' by <a href="' + (pullRequest.github.url || 'https://github.com/' + pullRequest.github.name) + '">' + pullRequest.github.name + '</a>';
        }
      }
    } else if (pullRequestCommit) {
      text += ' / <a href="' + pullRequestUrl + '/files/' + pullRequestCommit + '">' + pullRequestCommit + '</a>';
    }
    return text;
  };
  if (build.pullRequestsMetadata) {
    return build.pullRequestsMetadata.map((pullRequestMetadata, index) => {
      const pullRequestId = pullRequestMetadata.id;
      const pullRequest = build.pullRequests ? build.pullRequests[pullRequestId] : null;
      const nextPullRequestId = index + 1 < build.pullRequestsMetadata.length ? build.pullRequestsMetadata[index + 1].id : null;
      const nextPullRequest = nextPullRequestId !== null ? build.pullRequests[nextPullRequestId] : null;
      return toItem(pullRequestId, pullRequestMetadata.commit, pullRequest, nextPullRequest);
    }).join(', ');
  } else if (build.pullRequests) {
    const pullRequestIds = Object.keys(build.pullRequests);
    return pullRequestIds.map((pullRequestId, index) => {
      const pullRequest = build.pullRequests[pullRequestId];
      const nextPullRequest = index + 1 < pullRequestIds.length ? build.pullRequests[pullRequestIds[index + 1]] : null;
      return toItem(parseInt(pullRequestId), null, pullRequest, nextPullRequest);
    }).join(', ');
  } else {
    return '';
  }
}

function processPrivateCommand (botId, bot, msg, command, commandArgsRaw) {
  if (msg.chat.id !== ADMIN_USER_ID) {
    return;
  }
  switch (command) {
    case '/start': {
      // TODO?
      break;
    }
    case '/value': {
      if (commandArgsRaw) {
        db.get(commandArgsRaw, {valueEncoding: 'json'}, (err, value) => {
          if (err) {
            bot.sendMessage(msg.chat.id, '*Key not found!*', {parse_mode: 'MarkdownV2'}).catch(globalErrorHandler());
          } else {
            bot.sendMessage(msg.chat.id, '<code>' + JSON.stringify(value) + '</code>', {parse_mode: 'HTML'}).catch(globalErrorHandler());
          }
        });
      } else {
        bot.sendMessage(msg.chat.id, 'Key not specified.').catch(globalErrorHandler());
      }
      break;
    }
    case '/keys': {
      let keys = [];
      db.createReadStream({values: false})
      .on('data', (data)  => {
        keys.push('<code>' + data + '</code>');
      })
      .on('end', () => {
        sendArray(bot, msg.chat.id, keys, 'HTML');
      });
      break;
    }
    case '/values': {
      let values = [];
      db.createReadStream()
      .on('data', (data) => {
        values.push('<code>' + data.key + '</code>:\n<pre>' + data.value + '</pre>');
      })
      .on('end', () => {
        sendArray(bot, msg.chat.id, values, 'HTML', '\n\n');
      });
      break;
    }
    case '/abort': {
      if (!cur.pending_build) {
        bot.sendMessage(msg.chat.id, 'No build is in progress!').catch(globalErrorHandler());
        return;
      }
      cur.pending_build.abort();
      break;
    }
    case '/version': {
      getGitData((gitData) => {
        getAppVersion((version) => {
          let text = '<b>App Version</b>: <code>' + version.name + '</code>\n';
          text += '<b>Commit</b>: <a href="' + gitData.remoteUrl + '/tree/' + gitData.commit.long + '">' + gitData.commit.short + '</a>';
          if (gitData.branch) {
            text += '\n<b>Branch</b>: <code>' + gitData.branch + '</code>';
          }
          bot.sendMessage(msg.chat.id, text, {parse_mode: 'HTML'}).catch(globalErrorHandler());
        });
      }, true);
      break;
    }
    case '/clear': {
      db.clear();
      break;
    }
    case '/changes': {
      getLocalChanges((changes) => {
        if (changes) {
          bot.sendMessage(msg.chat.id, 'Current changes:\n\n<pre>' + escapeHtml(changes) + '</pre>', {parse_mode: 'HTML'}).catch(globalErrorHandler());
        } else {
          bot.sendMessage(msg.chat.id, 'No local changes found!').catch(globalErrorHandler());
        }
      });
      break;
    }
    case '/pull': {
      if (!cur.pending_build) {
        gitPull((log) => {
          bot.sendMessage(msg.chat.id, '<code>' + log + '</code>', {parse_mode: 'HTML'}).catch(globalErrorHandler());
        });
      } else {
        bot.sendMessage(msg.chat.id, 'Cannot pull fresh code, as some build is in progress. Use /abort to cancel it.');
      }
      break;
    }
    case '/deploy_stable':
    case '/deploy_beta':
    case '/deploy_alpha': // same as universal
    case '/deploy_pr':
    
    case '/build':
    case '/build_arm32':
    case '/build_arm64':
    case '/build_x86':
    case '/build_x64':
    case '/build_universal':

    case '/checkout':

    case '/update_sdk': {
      if (cur.build_no === -1 || cur.uploaded_version === -1) {
        bot.sendMessage(msg.chat.id, 'Please try again.').catch(globalErrorHandler());
        return;
      }

      if (LOCAL && command.startsWith('/deploy_')) {
        bot.sendMessage(msg.chat.id, command + ' is unavailable when running locally.').catch(globalErrorHandler());
        return;
      }

      getAppVersion((_version) => { getGitData((_gitData) => {
        if (!_version) {
          bot.sendMessage(msg.chat.id, 'Cannot detect app version!').catch(globalErrorHandler());
          return;
        }

        if (cur.pending_build) {
          bot.sendMessage(msg.chat.id, 'Another build is in progress! Abort with /abort').catch(globalErrorHandler());
          return;
        }

        const buildType = command === '/build' ? 'all' : command.includes('_') ? command.substring(command.indexOf('_') + 1) : command.substring(1);

        const allVariants = ['universal', 'arm64', 'arm32', 'x64', 'x86'];

        let specificVariant = buildType;
        if (!allVariants.includes(specificVariant)) {
          specificVariant = null;
        }

        const commandArgsList = commandArgsRaw ? commandArgsRaw.split(/[,\s]+/) : [];
        const commandArgs = commandArgsList.filter((arg) => arg.startsWith('--')).reduce((result, item) => {
          const index = item.indexOf('=');
          if (index !== -1) {
            const key = item.substring(2, index);
            const value = item.substring(index + 1);
            result[key] = value.match(/^[0-9]+$/g) ? parseInt(value) :
              value.match(/^[0-9]+\.[0-9]+$/g) ? parseFloat(value) :
              value;
          } else {
            const key = item.substring(2);
            result[key] = true;
          }
          return result;
        }, {});

        const isPRBuild = command === '/deploy_pr';
        const isPrivate = !(['/deploy_beta', '/deploy_stable', '/deploy_pr'].includes(command));
        const skipBuild = command === '/update_sdk';
        const outputChatId = isPRBuild ? PR_CHAT_ID : isPrivate ? (buildType === 'alpha' ? ALPHA_CHAT_ID : ADMIN_USER_ID) : BETA_CHAT_ID;
        const buildId = nextBuildId();
        const isSetup = '/checkout' === command;

        const pullRequestsMetadata = !isSetup ? null : commandArgsList.filter((arg) =>
          arg.match(/^[0-9]+$/gi)
        ).map((prId) =>
          parseInt(prId)
        ).filter((prId) => prId > 0)
         .sort()
         .map((id) => {
           return {id};
         })
         .concat(commandArgsList.filter((arg) =>
           arg.match(/^[0-9]+:[a-zA-Z0-9]+$/gi)
         ).map((idWithCommit) => {
           const data = idWithCommit.split(':');
           return {id: parseInt(data[0]), commit: data[1]};
         }).filter((pullRequest) => pullRequest.id > 0));

        const build = {
          id: buildId,
          type: buildType,
          version: _version,
          git: _gitData,
          serviceChatId: msg.chat.id,
          googlePlayTrack: buildType === 'stable' ? 'production' : ['beta', 'alpha'].includes(buildType) ? buildType : null,
          files: {}
        };
        if (pullRequestsMetadata && pullRequestsMetadata.length) {
          build.pullRequestsMetadata = pullRequestsMetadata;
          build.pullRequests = {};
        }
        if (outputChatId !== build.serviceChatId) {
          build.publicChatId = outputChatId;
        }
        cur.pending_build = build;
        if (build.googlePlayTrack) {
          build.telegramTrack = build.googlePlayTrack;
        } else if (build.publicChatId && !isPRBuild) {
          build.telegramTrack = 'private' + build.publicChatId;
        } else if (isPRBuild && build.pullRequestsMetadata) {
          build.telegramTrack = 'PR#' + build.pullRequestsMetadata.map((pullRequestsMetadata) => pullRequestsMetadata.id).join(',');
        }

        if (build.git.branch !== 'main' && (build.googlePlayTrack || build.telegramTrack)) {
          bot.sendMessage(msg.chat.id,
            'You are currently on a <b>' + build.git.branch + '</b> branch. Only <b>main</b> branch can be published.'
          );
          return;
        }

        build.variants = specificVariant != null ? [specificVariant] : allVariants;
        build.tasks = [];
        const initTask = {
          name: 'init',
          script: 'gradlew',
          args: [
            'clean',
            LOCAL ? '--info' : '--quiet',
            '--stacktrace',
            '--console=plain',
            '--parallel',
            '--max-workers=' + threadCount
          ]
        };
        const refreshInfoTask = {
          name: 'refreshInfo',
          act: (task, callback) => {
            getGitData((newGitData) => {
              if (!newGitData) {
                callback(1);
                return;
              }
              build.git = newGitData;

              getAppVersion(async (newVersion) => {
                if (!newVersion) {
                  callback(1);
                  return;
                }
                build.version = newVersion;
                const previousGooglePlayBuild = await findPublishedGooglePlayBuild(build);
                const previousTelegramBuild = await findPublishedTelegramBuild(build);
                if (!isPRBuild && (
                  (previousGooglePlayBuild && previousGooglePlayBuild.version.code >= build.version.code) ||
                  (previousTelegramBuild && previousTelegramBuild.version.code >= build.version.code)
                )) {
                  task.logPrivately(
                    'Version bump required. Current: ' + build.version.code +
                    ', previous: ' + Math.max(
                      previousGooglePlayBuild ? previousGooglePlayBuild.version.code : 0,
                      previousTelegramBuild ? previousTelegramBuild.version.code : 0
                    )
                  );
                  callback(1);
                  return;
                }
                build.previousTelegramBuild = previousTelegramBuild;
                build.previousGooglePlayBuild = previousGooglePlayBuild;
                callback(0);
              });
            });
          }
        };
        const buildDependenciesTask = {
          name: 'buildDependencies',
          silence: true,
          script: 'scripts/setup.sh',
          args: [
            '--skip-sdk-setup'
          ]
        };
        const newFetchGithubDetailsTask = (pullRequestId) => {
          return {
            name: 'fetchGithubDetails',
            act: (task, callback) => {
              const infoUrl = build.git.remoteUrl.replace(/(?<=(^https?:\/\/))github\.com(?=\/)/gi, 'api.github.com/repos') + '/pulls/' + pullRequestId;
              const url = new URL(infoUrl);
              fetchHttp(url, false, {
                headers: {
                  'User-Agent': 'Telegram-X-Publisher'
                }
              }).then((response) => {
                if (response.statusCode < 200 || response.statusCode >= 300) {
                  console.log('fetchHttp failed', response.statusCode, response.statusMessage, response.contentType, response.content);
                  callback(1);
                  return;
                }
                const githubInfo = JSON.parse(response.content);
                const author = githubInfo.user.login;
                const authorUrl = githubInfo.user.html_url;
                const pullRequest = build.pullRequests[pullRequestId];
                pullRequest.github = {
                  name: author,
                  url: authorUrl,
                  additions: githubInfo.additions || 0,
                  deletions: githubInfo.deletions || 0
                };
                callback(0);
              }).catch((e) => {
                console.log('fetchHttp failed', infoUrl, e);
                callback(1);
              })
            }
          };
        };
        if (command === '/checkout') {
          let appId = commandArgs['app.id'] || settings.app.id;
          let appName = commandArgs['app.name'] || settings.app.name;

          const updateSettingsTask = {
            name: 'updateSettings',
            act: (task, callback) => {
              let properties = 'sdk.dir=' + settings.ANDROID_SDK_ROOT + '\n' +
                'keystore.file=' + settings.TGX_KEYSTORE_PATH + '\n' +
                'app.download_url=' + settings.app.download_url + '\n' +
                'app.sources_url=' + settings.app.sources_url + '\n' +
                'telegram.api_id=' + settings.telegram.app.api_id + '\n' +
                'telegram.api_hash=' + settings.telegram.app.api_hash + '\n' +
                'youtube.api_key=' + settings.youtube.api_key + '\n';
              if (!empty(build.pullRequests)) {
                const prIds = build.pullRequestsMetadata.map((pullRequestMetadata) => pullRequestMetadata.id);
                const prAuthors = [... new Set(build.pullRequestsMetadata.map((pullRequestMetadata) => {
                  const pullRequest = build.pullRequests[pullRequestMetadata.id];
                  return pullRequest.github.name;
                }).filter((author) => author && author.length))];
                if (commandArgs.contest) {
                  if (prAuthors.length !== 1) {
                    console.log('Contest builds should be made by 1 author', !prAuthors.length ? 'empty' : prAuthors.join(', '));
                    callback(1);
                    return;
                  }
                  appName = 'X #' + prIds.join(',') + ' by ' + prAuthors.join(' & ');
                  appId = 'com.contest.' + prAuthors.map((author) => author.toLowerCase().replace(/[^a-zA-Z0-9_]/gi, '_')).sort().join('_');
                }

                properties += 'pr.ids=' + prIds.join(',') + '\n';
                for (const pullRequestId in build.pullRequests) {
                  const pullRequest = build.pullRequests[pullRequestId];
                  if (!pullRequest.github) {
                    callback(1);
                    return;
                  }
                  properties += 'pr.' + pullRequestId + '.commit_short=' + pullRequest.commit.short + '\n';
                  properties += 'pr.' + pullRequestId + '.commit_long=' + pullRequest.commit.long + '\n';
                  if (pullRequest.github) {
                    properties += 'pr.' + pullRequestId + '.author=' + pullRequest.github.name + '\n';
                    properties += 'pr.' + pullRequestId + '.author_url=' + pullRequest.github.url + '\n';
                    properties += 'pr.' + pullRequestId + '.additions=' + pullRequest.github.additions + '\n';
                    properties += 'pr.' + pullRequestId + '.deletions=' + pullRequest.github.deletions + '\n';
                  }
                  if (pullRequest.date) {
                    properties += 'pr.' + pullRequestId + '.date=' + pullRequest.date + '\n';
                  }
                }
              }
              const isExperimental = (appId !== settings.app.id || !!commandArgs.experimental);
              const dontObfuscate = !!commandArgs.dontobfuscate;
              properties +=
                'app.id=' + appId + '\n' +
                'app.name=' + appName + '\n' +
                'app.experimental=' + isExperimental + '\n' +
                'app.dontobfuscate=' + dontObfuscate + '\n';
              build.outputApplication = {
                id: appId,
                name: appName,
                experimental: isExperimental,
                dontObfuscate,
                isPRBuild
              };
              fs.writeFile(settings.TGX_SOURCE_PATH + '/local.properties',
                properties,
                'utf-8',
                (err) => {
                  if (err) {
                    console.error('Cannot create local.properties file', err);
                    callback(1);
                  } else {
                    callback(0);
                  }
                }
              );
            }
          }

          const resetTask = {
            name: 'reset',
            silence: true,
            script: 'scripts/force-clean.sh'
          };
          const currentBranch = commandArgs.branch || 'main';
          const checkoutTask = {
            name: 'checkout' + (currentBranch !== 'main' ? 'Branch' : ''),
            cmd: 'git clean -xfdf && \
                  git submodule foreach --recursive git clean -xfdf && \
                  git fetch origin && \
                  (git checkout ' + currentBranch + ' --recurse-submodules || git switch -c ' + currentBranch + ' origin/' + currentBranch + ') && \
                  git reset --hard origin/' + currentBranch + ' && \
                  git pull && \
                  git submodule foreach --recursive git reset --hard && \
                  git submodule update --init --recursive'
          };
          build.tasks.push(resetTask);
          build.tasks.push(checkoutTask);
          if (build.pullRequestsMetadata) {
            if (LOCAL)
              throw Error('Unsupported!');

            for (let i = 0; i < build.pullRequestsMetadata.length; i++) {
              const isSecondary = i > 0;
              const pullRequest = build.pullRequestsMetadata[i];
              const pullRequestId = pullRequest.id;

              const preparePrTask = {
                name: 'fetchPr-' + pullRequestId + (pullRequest.commit ? ':' + pullRequest.commit : ''),
                cmd: '(git branch -D pr-' + pullRequestId + ' || true) && \
                      ' + (commandArgs.force ?
                            '(git fetch -f origin pull/' + pullRequestId + '/head:pr-' + pullRequestId + ' || git rev-parse --quiet --verify pr-' + pullRequestId + ')' :
                            'git fetch -f origin pull/' + pullRequestId + '/head:pr-' + pullRequestId
                          ) + '&& \
                      ' + (isSecondary ? 'git stash &&' : '') + ' \
                      git checkout pr-' + pullRequestId + (
                        pullRequest.commit ? ' && \
                        git reset --hard ' + pullRequest.commit : ''
                      )
              };
              build.tasks.push(preparePrTask);

              const updatePrInfoTask = {
                name: 'refreshPrInfo-' + pullRequestId,
                act: (task, callback) => {
                  getGitData((newGitData) => {
                    if (newGitData) {
                      build.pullRequests[pullRequestId] = {
                        commit: newGitData.commit,
                        date: newGitData.date
                      };
                      callback(0);
                    } else {
                      callback(1);
                    }
                  });
                }
              };
              build.tasks.push(updatePrInfoTask);

              const fetchGithubDetailsTask = newFetchGithubDetailsTask(pullRequestId);
              build.tasks.push(fetchGithubDetailsTask);

              const squashPrTask = {
                name: 'squashPr-' + pullRequestId,
                cmd: 'git merge ' + currentBranch + ' -m "Sync with ' + currentBranch + '" && \
                      git checkout ' + currentBranch + ' && \
                      ' + (isSecondary ? 'git stash pop &&' : '') + ' \
                      git merge pr-' + pullRequestId + ' --squash --autostash && \
                      git branch -D pr-' + pullRequestId
              };
              build.tasks.push(squashPrTask);
            }
          }
          build.tasks.push(refreshInfoTask);
          build.tasks.push(updateSettingsTask);
          build.tasks.push(initTask);
          build.tasks.push(buildDependenciesTask);
        } else {
          build.tasks.push(refreshInfoTask);
        }
        if (!command.startsWith('/checkout') && command !== '/update_sdk') {
          const restorePullRequestsListTask = {
            name: 'restorePullRequestsList',
            act: (task, callback) => {
              fs.readFile(settings.TGX_SOURCE_PATH + '/local.properties', 'utf-8',  (err, data) => {
                if (err) {
                  callback(1);
                  return;
                }
                build.outputApplication = {
                  id: getProperty(data, 'app.id') || settings.app.id,
                  name: getProperty(data, 'app.name') || settings.app.name,
                  experimental: getProperty(data, 'app.experimental') === 'true',
                  dontObfuscate: getProperty(data, 'app.dontobfuscate') === 'true',
                  isPRBuild
                };
                let prIds = getProperty(data, 'pr.ids');
                if (prIds) {
                  prIds = prIds.split(',').map((id) => parseInt(id)).filter((id) => id > 0).sort();
                }
                if (!prIds || !prIds.length) {
                  callback(0);
                  return;
                }
                if (isPRBuild && !build.telegramTrack) {
                  build.telegramTrack = 'PR#' + prIds.join(',');
                }
                build.pullRequests = {};
                for (let i = 0; i < prIds.length; i++) {
                  const pullRequestId = prIds[i];
                  build.pullRequests[pullRequestId] = {
                    commit: {
                      short: getProperty(data, 'pr.' + pullRequestId + '.commit_short'),
                      long: getProperty(data, 'pr.' + pullRequestId + '.commit_long'),
                    },
                    date: getProperty(data, 'pr.' + pullRequestId + '.date'),
                    github: {
                      name: getProperty(data, 'pr.' + pullRequestId + '.author'),
                      url: getProperty(data, 'pr.' + pullRequestId + '.author_url'),
                      additions: parseInt(getProperty(data, 'pr.' + pullRequestId + '.additions')) || 0,
                      deletions: parseInt(getProperty(data, 'pr.' + pullRequestId + '.deletions')) || 0
                    }
                  }
                }
                build.pullRequestsMetadata = prIds.map((id) => {
                  const pullRequest = build.pullRequests[id];
                  if (pullRequest) {
                    return {id, commit: pullRequest.commit.short};
                  } else {
                    return {id};
                  }
                });
                let remaining = prIds.length;
                let finished = false;
                for (let i = 0; i < prIds.length; i++) {
                  const fetchGithubDetailsTask = newFetchGithubDetailsTask(prIds[i]);
                  fetchGithubDetailsTask.act(task, (code) => {
                    if (finished)
                      return;
                    if (code !== 0) {
                      finished = true;
                      callback(code);
                      return;
                    }
                    remaining--;
                    if (remaining === 0) {
                      finished = true;
                      callback(0);
                    }
                  })
                }
                callback(0);
              });
            }
          };
          build.tasks.push(restorePullRequestsListTask);
          build.variants.forEach((originalVariant) => {
            const variant = ucfirst(originalVariant);
            if (!skipBuild) {
              const buildTask = {
                name: 'assemble' + variant,
                script: 'gradlew',
                args: [
                  'assemble' + variant + 'Release',
                  LOCAL ? '--info' : '--quiet',
                  '--stacktrace',
                  '--console=plain',
                  '--parallel',
                  '--max-workers=' + threadCount
                ]
              };
              build.tasks.push(buildTask);
            }
            build.tasks.push({
              name: 'verify' + variant,
              act: (task, callback) => {
                getBuildFiles(build, originalVariant, (files) => {
                  if (!build.aborted && files) {
                    build.files[originalVariant] = files;
                    if (files.apkFile.checksum) {
                      traceBuiltApk(build, task, originalVariant, files.apkFile.checksum);
                      if (files.apkFile.checksum.sha256) {
                        task.logPublicly(files.apkFile.checksum.sha256);
                      }
                    }
                    callback(0);
                  } else {
                    callback(1);
                  }
                });
              }
            });
            build.tasks.push({
              name: 'upload' + variant,
              isAsync: true,
              act: (task, callback) => {
                return uploadToTelegram(bot, task, build, originalVariant, callback);
              }
            });
            if (build.publicChatId && (build.telegramTrack || isPRBuild) && originalVariant === 'universal' && build.variants.length > 1) {
              build.tasks.push({
                name: 'publishTelegramInternal',
                needsAwait: true,
                act: (task, callback) => {
                  return publishToTelegram(bot, task, build, callback, isPRBuild ? INTERNAL_CHAT_ID : ALPHA_CHAT_ID, true, false);
                }
              })
            }
          });

          if (build.publicChatId && (build.telegramTrack || isPRBuild)) {
            const id = isPRBuild ? 'PR' : build.telegramTrack.startsWith('private') ? 'Private' : ucfirst(build.telegramTrack);
            const targetChatId = (build.googlePlayTrack === 'production') ? ALPHA_CHAT_ID : build.publicChatId;
            build.tasks.push({
              name: 'publishTelegram' + id + (build.googlePlayTrack === 'production' ? 'Draft' : ''),
              needsAwait: true,
              act: (task, callback) => {
                return publishToTelegram(bot, task, build, callback, targetChatId, false, true);
              }
            });
          }

          if (!LOCAL && build.googlePlayTrack) {
            build.tasks.push({
              name: 'publishGooglePlay' + ucfirst(build.googlePlayTrack) + (build.googlePlayTrack === 'production' ? 'Draft' : ''),
              isAsync: true,
              act: (task, callback) => {
                return uploadToGooglePlay(task, build, callback);
              }
            });
          }
        }

        if (command === '/update_sdk') {
          build.tasks.push({
            name: 'updateSdk',
            script: 'scripts/setup-sdk.sh'
          });
        }
        
        const replyMarkup = JSON.stringify({inline_keyboard: [[{text: 'Cancel', callback_data: 'abort' + buildId}]]});
        build.asString = (isPublic, shorten) => {
          const commitUrl = '<a href="' + build.git.remoteUrl + '/tree/' + build.git.commit.long + '">' + build.git.commit.short + '</a>';
          const fromToCommit = getFromToCommit(build);
          const changesUrl = fromToCommit ? '<a href="' + build.git.remoteUrl + '/compare/' + fromToCommit.commit_range + '">' + fromToCommit.commit_range + '</a>' : null;
          let result = null;
          if (isPublic) {
            const displayTrack =
              build.googlePlayTrack === 'production' ? 'stable' :
              build.googlePlayTrack ? build.googlePlayTrack :
              build.telegramTrack ? build.telegramTrack :
              null;
            result = '<code>' + build.version.name + (displayTrack ? ' ' + displayTrack : '') + '</code>';
            if (build.aborted) {
              if (build.endTime) {
                result += ' <b>canceled</b>.';
              } else {
                result += ' is canceling…';
              }
            } else if (build.endTime) {
              result += build.error ? ' <b>deploy failed</b>.' :
                build.googlePlayTrack ? ' <a href="' + MARKET_URL + '"><b>' + (build.googlePlayTrack === 'production' ? 'sent to review' : 'released') + '</b></a>.' :
                ' <b>released</b>.';
            } else {
              result += ' is assembling…';
            }

            result += '\n';
          } else {
            result = '<code>' + command + (isPrivate && commandArgsRaw ? ' ' + commandArgsRaw : '') + '</code>';
            if (build.aborted) {
              if (build.endTime) {
                result += ' <b>canceled</b>.';
              } else {
                result += ' is canceling…';
              }
            } else if (build.endTime) {
              result += ' <b>finished.</b>';
            } else {
              result += ' in progress…';
            }
            result += '\n\n';
            result += '<b>Version</b>: ' + '<code>' + build.version.name + '</code>';
          }
          if (changesUrl) {
            result += '\n<b>Changes from ' + fromToCommit.from_version + '</b>: ' + changesUrl;
          } else {
            result += '\n<b>Commit</b>: ' + commitUrl;
            if (build.git.date) {
              result += ', ' + toDisplayDate(build.git.date);
            }
          }
          if (build.pullRequestsMetadata || !empty(build.pullRequests)) {
            result += '\n<b>Pull requests</b>: ' + toDisplayPullRequestList(build);
          }
          if (commandArgsRaw && ((isPublic && build.endTime && !build.error && !build.aborted) || (!isPublic && !isPrivate))) {
            result += '\n\n' + commandArgsRaw.trim();
          }
          result += '\n\n';
          if (build.endTime && !build.error && isPublic && !build.aborted) {
            if (build.googlePlayTrack === 'alpha' || build.googlePlayTrack === 'beta') {
              result += 'Google Play <b>' + (build.googlePlayTrack === 'beta' ? '<a href="' + TESTING_URL + '">' : '') + build.googlePlayTrack + (build.googlePlayTrack === 'beta' ? '</a>' : '') + '</b> will be available within an hour.\n';
            } else if (build.googlePlayTrack === 'production') {
              result += 'An update will become available for all users gradually once Google Play review will be finished.\n';
            }
            const variantLinks = [];
            if (build.publicMessages) {
              for (let i = 0; i < build.publicMessages.length; i++) {
                const publicMessage = build.publicMessages[i];
                if (publicMessage.url) {
                  variantLinks.push('<a href="' + publicMessage.url + '">' + publicMessage.variant + '</a>');
                }
              }
            }
            if (variantLinks.length) {
              result += 'You can install <b>APKs</b> directly: ' + variantLinks.join(', ') + '.';
            } else if (build.googlePlayTrack === 'production') {
              result += '<b>APKs</b> will be published separately.';
            } else {
              result += 'You can find <b>APKs</b> below.';
            }
          } else if (build.endTime && (build.error || build.aborted) && isPublic) {
            result += 'Another attempt might be made soon.';
          } else {
            for (let i = 0; i < build.tasks.length; i++) {
              let task = build.tasks[i];
              if (i > 0)
                result += '\n';
              result += '• <b>' + task.name + '</b>: ';
              if (task.finished) {
                result += '<b>finished in ' + duration(task.startTime, task.endTime) + '</b>';
              } else if (task.interrupted) {
                result += task.endTime ? '<b>aborted in ' + duration(task.startTime, task.endTime) + '</b>' : 'aborting…';
              } else if (task.error) {
                result += '<b>failed in ' + duration(task.startTime, task.endTime) + '!</b>';
              } else if (task.startTime) {
                result += 'in progress…';
                if (task.progress) {
                  result += ' <b>' + task.progress + '</b>';
                }
              } else if (build.aborted || build.error) {
                result += '<i>canceled</i>';
              } else {
                result += '<i>pending</i>';
              }
              const logs = isPublic ? task.publicLog : task.privateLog;
              if (logs) {
                if (shorten) {
                  if (logs.length) {
                    result += '\n&gt; ' + logs.length + ' log message' + (logs.length !== 1 ? 's' : '');
                  }
                } else {
                  logs.forEach((log) => {
                    result += '\n&gt; <code>' + escapeHtml(trimIndent(log).trim()) + '</code>';
                  });
                }
              }
            }
          }
          const time = (build.endTime || build.estimateDuration) ? (build.endTime ? duration(build.startTime, build.endTime, true) : '~' + duration(0, Math.round(build.estimateDuration / 1000) * 1000, true)) : null;
          if (isPublic) {
            if (time) {
              result += build.endTime ? '\n\n<i>Finished in <b>' + time + '</b></i>' : '\n\n<i>Finishing in ' + time + '</i>';
            }
          } else {
            result += '\n\n<i>' + cpuSignature + '</i>';
            if (time) {
              result += ': <i> ' + time + '</i>';
            }
          }
          result = result.trim();
          if (result.length > 4000) {
            if (!shorten) {
              return build.asString(isPublic, true);
            }
            result = result.substring(0, 3999) + '…';
          }
          return result;
        };
        build.updateMessage = async (isFinal) => {
          if (build.publicChatId && build.publicMessageId) {
            const text = build.asString(true);
            let params = {
              chat_id: build.publicChatId,
              message_id: build.publicMessageId,
              parse_mode: 'HTML',
              disable_web_page_preview: true
            };
            if (build.publicMessage !== text) {
              build.publicMessage = text;
              try {
                await bot.editMessageText(text, params);
              } catch (e) {
                console.error('Cannot update message', JSON.stringify(params), e);
                if (isFinal) {
                  let timeout = 0;
                  let success = false;
                  let retryCount = 10;
                  do {
                    timeout += 1500;
                    await sleep(Math.min(10000, timeout));
                    try {
                      await bot.editMessageText(text, params);
                      success = true;
                    } catch (e) {
                      console.error('Cannot retry update message', JSON.stringify(params), e, retryCount);
                    }
                  } while (!success && --retryCount > 0);
                }
              }
            }
          }
          if (build.serviceChatId && build.serviceMessageId) {
            const needMarkup = !build.aborted && !build.endTime;
            const text = build.asString();
            let params = {
              chat_id: build.serviceChatId,
              message_id: build.serviceMessageId,
              parse_mode: 'HTML',
              disable_web_page_preview: true
            };
            if (needMarkup) {
              params.reply_markup = replyMarkup;
            }
            if (build.message !== text || build.canBeCanceled !== needMarkup) {
              build.message = text;
              build.canBeCanceled = needMarkup;
              try {
                await bot.editMessageText(text, params);
              } catch (e) {
                console.error('Cannot update message', JSON.stringify(params), e);
              }
            }
          }
        };
        build.after = (callback) => {
          if (callback) {
            if (build.endTime) {
              callback();
              return;
            }
            if (!build.invokeAfter) {
              build.invokeAfter = [callback];
            } else {
              build.invokeAfter.push(callback);
            }
          }
        };
        build.abort = async (after) => {
          if (build.aborted || build.endTime) {
            build.after(after);
            return;
          }
          console.log('Aborting build ' + build.version.name);
          build.aborted = true;
          await build.updateMessage(true);
          if (build.publicMessages) {
            // Deleting APKs
            for (let i = 0; i < build.publicMessages.length; i++) {
              const messageId = build.publicMessages[i].message_id;
              if (messageId != 0) {
                await bot.deleteMessage(build.publicChatId, messageId);
                build.publicMessages[i] = 0;
              }
            }
          }
          if (build.publicMessageId && (new Date() - build.startTime) <= Math.round(1.5 * 60 * 1000) /*posted less than 1.5 minutes ago*/) {
            // Deleting build log
            const publicMessageId = build.publicMessageId;
            build.publicMessageId = 0;
            await bot.deleteMessage(build.publicChatId, publicMessageId);
          }
          for (let i = 0; i < build.tasks.length; i++) {
            const task = build.tasks[i];
            if (!task.endTime && task.startTime) {
              task.interrupted = true;
              if (task.process) {
                await killTask(task);
                await build.updateMessage(true);
              } else if (task.cancel) {
                await task.cancel();
              }
              break;
            }
          }
          build.after(after);
        };
        build.cleanup = async () => {
          await build.updateMessage(true);
          if (cur.pending_build && cur.pending_build.id === build.id) {
            cur.pending_build = null;
          }
        };
        build.step = () => {
          if (!build.startTime) {
            if (build.aborted)
              return true;
            build.startTime = new Date();
          }
          if (build.endTime) {
            return true;
          }
          let havePendingAsyncTasks = false;
          let haveErrors = false;
          let completeTaskCount = 0;
          for (let i = 0; i < build.tasks.length; i++) {
            const task = build.tasks[i];
            if (task.error) {
              haveErrors = true;
            }
            if (!task.error && task.startTime && task.endTime) {
              completeTaskCount++;
            }
            if (!build.aborted && !task.startTime && !haveErrors) {
              if (task.needsAwait && havePendingAsyncTasks) {
                return false;
              }
              task.startTime = new Date();
              task.privateLog = [];
              task.publicLog = [];
              task.logPrivately = (message) => {
                message = escapeHtml(trimIndent(message).trim());
                if (message) {
                  task.privateLog.push(message);
                  build.updateMessage();
                }
              };
              task.logPublicly = (message) => {
                task.logPrivately(message);
                message = escapeHtml(trimIndent(message).trim());
                if (message) {
                  task.publicLog.push(message);
                  build.updateMessage();
                }
              };
              const onDone = (code) => {
                if (task.endTime)
                  return;
                console.log('Finished task ' + task.name + ' with code ' + code);
                if (code != 0 && task.privateLog) {
                  console.log('Private task ' + task.name + ' log:\n' + task.privateLog.join('\n'));
                }
                task.endTime = new Date();
                task.process = null;
                task.exitCode = code;
                task.error = code != 0;
                if (task.error) {
                  build.error = true;
                }
                task.finished = !task.error;
                build.updateMessage();
                traceDuration('task_stat', task.name, task.startTime, task.endTime, task.finished);
                build.step();
              };
              if (task.cmd || task.script) {
                if (task.script) {
                  const args = task.args ? [task.script, ...task.args] : [task.script];
                  task.process = spawn('/bin/bash', args, {cwd: settings.TGX_SOURCE_PATH});
                } else {
                  const command = task.cmd + (task.args ? ' ' + task.args.join(' ') : '');
                  console.log('Executing command', command);
                  task.process = spawn('/bin/bash', ['-c', command], {cwd: settings.TGX_SOURCE_PATH});
                }
                task.process.stdout.on('data', (data) => {
                  if (!task.silence || LOCAL) {
                    console.log(`${data}`);
                  }
                });
                task.process.stderr.on('data', (data) => {
                  if (task.silence) {
                    console.error(`${data}`);
                  } else {
                    task.logPrivately(`${data}`);
                  }
                });
                task.process.on('close', onDone);
              } else {
                task.cancel = task.act(task, onDone);
              }

              build.updateMessage();
              if (task.isAsync) {
                havePendingAsyncTasks = true;
                continue;
              }
              return false;
            }

            if (task.startTime && !task.endTime) {
              if (task.isAsync) {
                havePendingAsyncTasks = true;
                continue;
              }
              return false;
            }
          }
          if (havePendingAsyncTasks) {
            return false;
          }
          if (completeTaskCount === build.tasks.length) {
            build.aborted = false;
          }
          build.endTime = new Date();
          build.cleanup().then(async () => {
            if (build.publicChatId && build.publicMessageId && !(build.aborted || build.error)) {
              try {
                await bot.pinChatMessage(build.publicChatId, build.publicMessageId);
              } catch (e) {
                console.log('Cannot pin chat message', e);
              }
            }
          });

          traceDuration('build_stat', build.type, build.startTime, build.endTime, !haveErrors);
          if (build.invokeAfter) {
            for (let i = 0; i < build.invokeAfter.length; i++) {
              build.invokeAfter[i]();
            }
          }

          return true;
        };
        estimateBuildDuration(build).then(() => {
          build.step();

          build.message = build.asString();
          build.canBeCanceled = true;

          bot.sendMessage(msg.chat.id, build.message, {
            parse_mode: 'HTML',
            reply_markup: replyMarkup,
            disable_web_page_preview: true
          }).then((message) => {
            build.serviceMessageId = message.message_id;
            build.updateMessage();
          }).catch(globalErrorHandler());

          if (build.publicChatId) {
            build.publicMessage = build.asString(true);
            bot.sendMessage(build.publicChatId, build.publicMessage, {
              parse_mode: 'HTML',
              disable_notification: true,
              disable_web_page_preview: true
            }).then((message) => {
              build.publicMessageId = message.message_id;
              build.updateMessage();
            }).catch(globalErrorHandler());
          }
        });
      }); });
      break;
    }
    default: {
      bot.sendMessage(
        msg.chat.id,
        'Unknown command:\n' + 
        '<pre><code class="language-javascript">' +
          escapeHtml(JSON.stringify(msg, null, 2)) +
        '</code></pre>',
        {parse_mode: 'HTML'}
      ).catch(globalErrorHandler());
      break;
    }
  }
}

function matchChecksum (text) {
  const result = text.length ? text.match(/^[a-fA-F0-9]+$/gi) : null;
  return result && result[0] ? result[0].toLowerCase() : null;
}

function getChecksumMessage (checksum, apk, displayChecksum) {
  let text = '';
  if (displayChecksum) {
    text += '<code>' + checksum + '</code> is a ';
    if (apk.hashAlgorithm) {
      text += '<b>' + toDisplayAlgorithm(apk.hashAlgorithm) + '</b> ';
    }
    text += 'hash that ';
  } else {
    text += 'This ';
    if (apk.hashAlgorithm) {
      text += '<b>' + toDisplayAlgorithm(apk.hashAlgorithm) + '</b> ';
    }
    text += 'hash ';
  }

  text += 'corresponds to ';
  text += '<b>' + (!apk.branch || apk.branch === 'main' ? 'official' : 'unofficial') + ' Telegram X</b> build.';

  if (apk.googlePlayTrack) {
    text += '\n\n';
    text += 'This build was published to <b>Google Play' + (apk.googlePlayTrack === 'stable' ? '' : ' ' + ucfirst(apk.googlePlayTrack)) + '</b>.';
  }

  text += '\n\n';
  text += '<b>Version</b>: <code>' + apk.version.name + '-' + getDisplayVariant(apk.variant) + '</code>\n';
  text += '<b>Commit</b>: <a href="' + apk.remoteUrl + '/tree/' + apk.commit.long + '">' + apk.commit.short + '</a>';
  if (apk.date) {
    text += ', ' + toDisplayDate(apk.date);
  }
  if (apk.pullRequestsMetadata || !empty(apk.pullRequests)) {
    text += '\n';
    text += '<b>Pull requests</b>: ' + toDisplayPullRequestList(apk);
  }
  return text;
}

function processPublicCommand (botId, bot, msg, command, commandArgs) {
  if (msg.text) {
    if (command === '/start') {
      const welcome = () => {
        bot.sendMessage(msg.chat.id,
          'Hello! I am the official <b>Telegram X</b> bot.\n\n' +
          'You can send me <b>checksum</b> of an <b>APK file</b> you downloaded, and I can tell whether it corresponds to any <b>Telegram X</b> build I am aware of.\n\n' + 
          '<b>Note</b>: you can always grab a fresh APK from @tgx_log.',
          {parse_mode: 'HTML'}
        ).catch(globalErrorHandler());
      };
      if (commandArgs === 'crash') {
        // Do nothing. Wait for incoming crash file.
      } else if (commandArgs === 'feedback') {
        bot.sendMessage(msg.chat.id, 'Hello! I am the official <b>Telegram X</b> bot.\n\n' +
          'It seems that you want to leave feedback on <b>Telegram X</b>.\n\n' +
          'If you want to just write a public app review, you can leave it on <a href="' + MARKET_URL + '">Google Play</a>.\n\n' + 
          'Meanwhile you can send me <b>checksum</b> of an <b>APK file</b> you downloaded from anywhere, and I can tell whether it corresponds to any <b>Telegram X</b> build I am aware of.',
          {parse_mode: 'HTML'}
        ).catch(globalErrorHandler());
      } else if (matchChecksum(commandArgs)) {
        const checksum = matchChecksum(commandArgs);
        findApkByHash(checksum, (err, apk) => {
          if (err) {
            bot.sendMessage(msg.chat.id,
              '<code>' + checksum + '</code> seems to be a hash, but it does not correspond to any <b>Telegram X</b> build I am aware of.',
              {parse_mode: 'HTML'/*, reply_to_message_id: msg.message_id*/}
            ).catch(globalErrorHandler());
          } else {
            bot.sendMessage(msg.chat.id, getChecksumMessage(checksum, apk, true),
              {
                parse_mode: 'HTML',
                disable_web_page_preview: true /*, reply_to_message_id: msg.message_id*/
              }
            ).catch(globalErrorHandler());
          }
        });
      } else {
        welcome();
      }
      return true;
    }
    if (!command) {
      const checksum = matchChecksum(msg.text);
      if (checksum) {
        findApkByHash(checksum, (err, apk) => {
          if (err) {
            bot.sendMessage(msg.chat.id,
              'This hash does not correspond to any <b>Telegram X</b> I am aware of.',
              {parse_mode: 'HTML', reply_to_message_id: msg.message_id}
            ).catch(globalErrorHandler());
          } else {
            bot.sendMessage(msg.chat.id, getChecksumMessage(checksum, apk, false),
              {
                parse_mode: 'HTML',
                disable_web_page_preview: true,
                reply_to_message_id: msg.message_id
              }
            ).catch(globalErrorHandler());
          }
        });
        return true;
      }
    }
  } else if (msg.document) {
    bot.sendMessage(msg.chat.id,
      'Sorry, I can currently process only <b>checksums</b>, not files themselves.',
      {parse_mode: 'HTML', reply_to_message_id: msg.message_id}
    ).catch(globalErrorHandler());
    return (msg.document.file_name && msg.document.file_name.endsWith('.apk')) ||
      (msg.document.mime_type && msg.document.mime_type === APK_MIME_TYPE);
  }
}

function messageCallback (botId, bot, msg) {
  if (msg.chat.type !== 'private')
    return;

  if (msg.from && msg.from.is_bot) {
    console.error('Received message from bot',
      'from:', JSON.stringify(msg.from),
      'chat:', JSON.stringify(msg.chat),
      'text:', msg.text || 'null'
    );
    return;
  }
  
  storeObject('user', msg.from);
  storeObject('user', msg.forward_from);
  storeObject('chat', msg.sender_chat);
  storeObject('chat', msg.chat);

  let command = null, commandArgs = '';

  if (msg.text && msg.entities && msg.entities.length) {
    for (let i = 0; i < msg.entities.length; i++) {
      const entity = msg.entities[i];
      if (entity.type === 'bot_command' && entity.offset === 0) {
        command = entity.length === msg.text.length ? msg.text : msg.text.substring(0, entity.length);
        commandArgs = msg.text.length > command.length + 1 ? msg.text.substring(command.length + 1) : '';
        break;
      }
    }
  }

  if (botId === 'public' && (msg.chat.username == null || ![BETA_CHAT_ID, PR_CHAT_ID].includes(msg.chat.username))) {
    try {
      const success = processPublicCommand(botId, bot, msg, command, commandArgs);
      if (success) {
        return;
      }
    } catch (e) {
      console.log(e);
      return;
    }
  }
  if (botId === 'private' && msg.chat.id === ADMIN_USER_ID && !msg.reply_to_message) {
    processPrivateCommand(botId, bot, msg, command, commandArgs);
    return;
  }

  // Chat through forwarded messages

  /*if (!msg.from || msg.from.id !== ADMIN_USER_ID) {
    bot.forwardMessage(ADMIN_USER_ID, msg.chat.id, msg.message_id).then((forwardedMessage) => {
      db.put('origin_' + botId + '_' + forwardedMessage.message_id, [msg.chat.id, msg.message_id], {valueEncoding: 'json'});
    }).catch(globalErrorHandler());
    return;
  }
  if (msg.chat.id === ADMIN_USER_ID && msg.reply_to_message) {
    db.get('origin_' + botId + '_' + msg.reply_to_message.message_id, {valueEncoding: 'json'}, (err, origin) => {
      if (err)
        return;
      let chatId = origin[0];
      let messageId = origin.length > 1 ? origin[1] : 0;
      bot.copyMessage(chatId, msg.chat.id, msg.message_id, {
        reply_to_message_id: messageId,
      }).catch(globalErrorHandler());
    });
    return;
  }*/
}

function queryCallback (botId, bot, query) {
  storeObject('user', query.from);
  storeObject('user', query.message ? query.message.from : null);
  storeObject('chat', query.chat);

  if (botId === 'private' && query.from.id === ADMIN_USER_ID &&
      cur.pending_build && query.data === 'abort' + cur.pending_build.id) {
    cur.pending_build.abort(() => {
      bot.answerCallbackQuery(query.id);
    });
    return;
  }

  bot.answerCallbackQuery(query.id);
}

bots.forEach((bot) => {
  bot.bot.on('callback_query', (query) => queryCallback(bot.id, bot.bot, query));
  bot.bot.on('message', (msg) => messageCallback(bot.id, bot.bot, msg));
  bot.bot.on('channel_post', (msg) => messageCallback(bot.id, bot.bot, msg));
  bot.bot.on('error', globalErrorHandler());
  bot.bot.on('polling_error', (error) => {
    bot.bot.sendMessage(ADMIN_USER_ID, 'Polling error…\n' + error).catch(globalErrorHandler());
  });
});
/*bot.on('inline_query', (query) => {
  console.log('inline query', JSON.stringify(query));
});
bot.on('chosen_inline_result', (result) => {
  console.log('inline result', JSON.stringify(result));
});*/

async function onExit (signal, arg1, arg2, callback) {
  cur.exiting = true;
  if (cur.pending_build && cur.pending_build.abort) {
    console.log('Aborting current build manually…');
    cur.pending_build.abort(() => {
      onExit(signal, arg1, arg2, callback);
    });
    return;
  }
  if (!isOffline()) {
    try {
      await botMap['private'].sendMessage(ADMIN_USER_ID, 'Bot stopped.');
    } catch (ignored) {}
  }
  await stopServer();
  await db.close();
  callback();
}

['SIGTERM', 'SIGINT', 'uncaughtException', 'unhandledRejection'].forEach((signal) => {
  process.on(signal, (arg1, arg2) => {
    console.log('Received', signal, arg1, arg2);
    if (signal === 'unhandledRejection')
      return;

    if (!isOffline()) {
      botMap['private'].sendMessage(ADMIN_USER_ID, '*' + signal + '* received, bot is stopping\\.\\.\\.', {parse_mode: 'MarkdownV2'}).catch(globalErrorHandler());
    }

    onExit(signal, arg1, arg2, () => {
      process.exit(signal === 'uncaughtException' || signal === 'unhandledRejection' ? 1 : 0);
    });
  });
});

// EXIT handling
process.on('exit', () => {
  // Cleanup
  console.log('App is closing…');
});

function sorted (unordered) {
  return Object.keys(unordered).sort().reduce(
    (obj, key) => { 
      const val = unordered[key];
      if (typeof val === 'object') {
        obj[key] = JSON.stringify(sorted(val), null, 2);
      } else {
        obj[key] = val;
      }
      return obj;
    }, 
    {}
  );
}

botMap['private'].sendMessage(ADMIN_USER_ID,
  '<b>Bot has started.</b>\n\nPID: <code>' + process.pid +
  '</code>\npwd: <code>' + process.cwd() + '</code>\nenv:\n<pre>' +
  JSON.stringify(sorted(process.env), null, 2) +
  '</pre>', {parse_mode: 'HTML'}
).catch(globalErrorHandler());
