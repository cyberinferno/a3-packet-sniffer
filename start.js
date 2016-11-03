#!/usr/bin/env node

'use strict';

var exec = require('child_process').exec;
var fs = require('fs');
var crypt = require('./crypt.js');
var pcapp = require('pcap-parser');
var config = {
  "constant_key_1": 2366183,
  "constant_key_2": 1432754,
  "dynamic_key": 79984829
};
const COMMAND_SHOW_INTERFACES = 'windump -D';

crypt.prepare(config);
if (!fs.existsSync('windump.exe') && !fs.existsSync('WinDump.exe')) {
  console.log('Please install WinPcap, download WinDump and place WinDump.exe in the current folder!');
  process.exit();
}
if (process.argv.length < 3) {
  console.log('Usage:');
  console.log('To start capturing packets from a server: node start --inferface=eth0 --ip=103.231.209.227');
  console.log('To list available interfaces to listen: node start --show-interfaces');
  process.exit();
}
var fileName = Date.now() + '.pcap';
var baseCommand = 'windump -w logs/' + fileName;
var commandToExecute = '';
for (var i = 2; i < process.argv.length; i++) {
  if (process.argv[i].trim() === '--show-interfaces') {
    commandToExecute = COMMAND_SHOW_INTERFACES;
    break;
  }
  var splitArgument = process.argv[i].trim().split('=');
  if (splitArgument.length !== 2) {
    commandToExecute = '';
    break;
  }
  if (commandToExecute === '') {
    commandToExecute = baseCommand;
  }
  console.log(splitArgument[0]);
  switch (splitArgument[0].trim().toLowerCase()) {
    case '--interface':
      commandToExecute += ' -i ' + splitArgument[1];
      break;
    case '--ip':
      commandToExecute += ' -n "src ' + splitArgument[1] + ' or dst ' + splitArgument[1] + ' and not src port 80 and not dst port 80"';
      break;
  }
}
if (commandToExecute === '') {
  console.log('Usage:');
  console.log('To start capturing packets from a server: node start --interface=eth0 --ip=103.231.209.227');
  console.log('To list available interfaces to listen: node start --show-interfaces');
  process.exit();
}
if (commandToExecute !== COMMAND_SHOW_INTERFACES) {
  console.log('Started capturing A3 packets. Press Ctrl + C to stop capturing and process packets!');
  console.log('Executing: ' + commandToExecute);
}
exec(commandToExecute, function (error, stdout, stderr) {
  if (error) {
    console.log(stderr);
  } else {
    if (stdout.trim() !== '') {
      console.log(stdout);
    }
    if (commandToExecute !== COMMAND_SHOW_INTERFACES && fs.existsSync('./logs/' + fileName)) {
      var parser = pcapp.parse('./logs/' + fileName);
      var dir = './logs/' + fileName.split('.')[0];
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir);
      }
      if (!fs.existsSync(dir + '/original')) {
        fs.mkdirSync(dir  + '/original');
      }
      if (!fs.existsSync(dir + '/decrypted')) {
        fs.mkdirSync(dir + '/decrypted');
      }
      parser.on('packet', function (packet) {
        if (packet.header.originalLength !== 0 && packet.header.capturedLength !== 0) {
          fs.writeFileSync(dir + '/original/' + packet.header.timestampSeconds + '_' + packet.header.timestampMicroseconds + '_' + packet.header.originalLength + '.bin', packet.data);
        }
      });
    }
  }
});
process.on('SIGINT', function () {
  console.log('Received interrupt signal. Stopping capture and processing packets!');
});
