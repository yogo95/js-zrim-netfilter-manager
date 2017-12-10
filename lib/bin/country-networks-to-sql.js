#!/usr/bin/env node

const _ = require('lodash'),
  util = require('util'),
  defaultLogger = require('js-zrim-proxy-logger').defaultLogger,
  ArgumentParser = require('argparse').ArgumentParser,
  WinstonProxyLogger = require('js-zrim-proxy-logger').WinstonProxyLogger,
  jsErrors = require('js-zrim-errors'),
  commonErrors = jsErrors.common,
  fse = require('fs-extra'),
  Joi = require('joi');


const APP_VERSION = require('./../../package.json').version;


const argsParser = new ArgumentParser({
  version: APP_VERSION,
  addHelp: true,
  description: 'Convert file from http://software77.net/geo-ip/ to sql'
});

argsParser.addArgument(
  [ '-i', '--input-file-path' ],
  {
    help: 'The input file as CSV',
    required: true,
    dest: 'inputFilePath',
    action: 'store',
    metavar: 'input_file_path'
  }
);

argsParser.addArgument(
  [ '-o', '--output-file-path' ],
  {
    help: 'Ouput file path',
    required: true,
    dest: 'outputFilePath',
    action: 'store',
    metavar: 'output_file_path'
  }
);

const usageArgs = argsParser.parseArgs();

const applicationWorkflow = {
  instance: {},
  context: {
    logger: new WinstonProxyLogger({
      target: defaultLogger.getDefaultLogger(null),
      prefixes: [`BlackListCvsToSql:${APP_VERSION}`]
    }),
    usageArgs: usageArgs,
    configuration: {}
  }
};

Promise.resolve()
  .then(() => {
    return new Promise((resolve, reject) => {
      const context = applicationWorkflow.context;
      const logger = context.logger.of({
        prefixes: ['ReadInput']
      });

      fse.readFile(context.usageArgs.inputFilePath)
        .then(data => {
          context.rawInputData = data.toString();
          resolve();
        })
        .catch(reject);
    });
  })
  .then(() => {
    return new Promise((resolve, reject) => {
      const context = applicationWorkflow.context;
      const logger = context.logger.of({
        prefixes: ['Convert']
      });

      const generateUuid = require('uuid/v4');

      let lines = context.rawInputData.replace('\r', '').split('\n');
      lines = _.filter(lines, line => !_.startsWith(line, '#') && line.length > 0);

      const sqlLines = [
        'SET statement_timeout = 0;',
        'SET lock_timeout = 0;',
        'SET idle_in_transaction_session_timeout = 0;',
        "SET client_encoding = 'UTF8';",
        'SET standard_conforming_strings = on;',
        'SET check_function_bodies = false;',
        'SET client_min_messages = warning;',
        'SET row_security = off;',
        'SET search_path = security, pg_catalog;',
        'COPY security.networks (uuid, network, registry, ctry, cntry, country, assigned, inserted) FROM stdin;'
      ];
      _.each(lines, line => {
        let parts = line.split(',');
        parts = _.map(parts, p => p.trim());
        parts = _.map(parts, p => p.substr(1, p.length - 2));

        const intToIpStr = num => {
          return ((num >> 24) & 0xFF) + '.' + ((num >> 16) & 0xFF) + '.' + ((num >> 8) & 0xFF) + '.' + (num & 0xFF);
        };

        const maskToNum = size => {
          let n = 0;
          let v = size;
          for (let i = 0; i < 32; i++) {
            if (v & 0x1) {
              ++n;
            } else {
              break;
            }

            v >>= 1;
          }

          return 32 - n;
        };

        const from = parseInt(parts[0]), to = parseInt(parts[1]);
        const uuid = generateUuid();
        const assigned = new Date(parseInt(parts[3])).toISOString(),
          insertedAt = new Date(Date.now()).toISOString();
        const range = {
          from: intToIpStr(from),
          to: intToIpStr(to),
          size: to - from,
          mask: maskToNum(to - from)
        };

        range.cidr = `${range.from}/${range.mask}`;

        sqlLines.push(`${uuid}\t${range.cidr}\t${parts[2]}\t${parts[4]}\t${parts[5]}\t${parts[6]}\t${assigned}\t${insertedAt}`);
      });

      fse.outputFile(context.usageArgs.outputFilePath, sqlLines.join('\n'))
        .then(resolve)
        .catch(reject);
    });
  })
  .catch(error => {
    process.stderr.write(`Failed to process: ${error.message}\n${error.stack}\n`);
    process.exit(1);
  });
