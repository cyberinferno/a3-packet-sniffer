#!/usr/bin/env node

'use strict';

var fs = require('fs');
var crypt = require('./crypt.js');
var pcapp = require('pcap-parser');
var config = {
  "constant_key_1": 2366183,
  "constant_key_2": 1432754,
  "dynamic_key": 79984829
};

crypt.prepare(config);

if (process.argv.length < 3) {
  console.log('Usage:');
  console.log('node parse --input=file.pcap --output=D:/');
  process.exit();
}
if (!fs.existsSync('windump.exe')) {
  console.log('Input file is not found or cannot be accessed!');
  process.exit();
}
var inputFile = '';
var outputPath = '';
for (var i = 2; i < process.argv.length; i++) {
  var splitArgument = process.argv[i].trim().split('=');
  if (splitArgument.length !== 2) {
    continue;
  }
  switch (splitArgument[0]) {
    case '--input':
      inputFile = splitArgument[1];
      break;
    case '--output':
      outputPath = splitArgument[1];
      break;
  }
}
if (inputFile === '' || outputPath === '') {
  console.log('Usage:');
  console.log('node parse --input=file.pcap --output=D:/');
  process.exit();
}
var parser = pcapp.parse(inputFile);
if (!fs.existsSync(outputPath)) {
  fs.mkdirSync(outputPath);
}
if (!fs.existsSync(outputPath + '/original')) {
  fs.mkdirSync(outputPath  + '/original');
}
if (!fs.existsSync(outputPath + '/decrypted')) {
  fs.mkdirSync(outputPath + '/decrypted');
}
parser.on('packet', function (packet) {
  if (packet.header.originalLength !== 0 && packet.header.capturedLength !== 0) {
    console.log('Parsing packet of length ' + packet.header.originalLength);
    fs.writeFileSync(outputPath + '/original/' + packet.header.timestampSeconds + '_'
      + packet.header.timestampMicroseconds + '_' + packet.header.originalLength + '.bin', packet.data);
    fs.writeFileSync(outputPath + '/decrypted/' + packet.header.timestampSeconds + '_'
      + packet.header.timestampMicroseconds + '_' + packet.header.originalLength + '.bin', crypt.decrypt(packet.data));
  }
});
