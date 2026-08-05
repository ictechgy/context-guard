#!/usr/bin/env node
'use strict';

const { launch } = require('./launcher.cjs');

process.exitCode = launch('receipt', process.argv.slice(2), __filename);
