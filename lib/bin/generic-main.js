#!/usr/bin/env node

const _ = require('lodash'),
  util = require('util'),
  defaultLogger = require('js-zrim-proxy-logger').defaultLogger,
  ArgumentParser = require('argparse').ArgumentParser,
  WinstonProxyLogger = require('js-zrim-proxy-logger').WinstonProxyLogger,
  jsErrors = require('js-zrim-errors'),
  commonErrors = jsErrors.common,
  Joi = require('joi');


const APP_VERSION = require('./../../package.json').version;


const argsParser = new ArgumentParser({
  version: APP_VERSION,
  addHelp: true,
  description: 'Generic Netfilter Genenrator'
});

argsParser.addArgument(
  [ '-i', '--id' ],
  {
    help: 'The configuration id to use',
    required: true,
    dest: 'configurationId',
    action: 'store',
    metavar: 'configuration_id'
  }
);

argsParser.addArgument(
  [ '-c', '--config-file' ],
  {
    help: 'Configuration file',
    required: true,
    dest: 'configurationFilePath',
    action: 'store',
    metavar: 'configuration_file_path'
  }
);

argsParser.addArgument(
  [ '-a', '--action' ],
  {
    help: 'Action to perform',
    choices: ['install', 'uninstall'],
    required: true,
    dest: 'action',
    action: 'store'
  }
);

argsParser.addArgument(
  [ '-j', '--job' ],
  {
    help: 'The job to use',
    required: true,
    dest: 'jobName',
    action: 'store'
  }
);

argsParser.addArgument(
  [ '-p', '--print' ],
  {
    help: 'Print rules',
    dest: 'printRules',
    action: 'storeTrue',
    defaultValue: false
  }
);

argsParser.addArgument(
  [ '-s', '--apply' ],
  {
    help: 'Apply the action',
    dest: 'apply',
    action: 'storeTrue',
    defaultValue: false
  }
);

const usageArgs = argsParser.parseArgs();

const applicationWorkflow = {
  instance: {},
  context: {
    logger: new WinstonProxyLogger({
      target: defaultLogger.getDefaultLogger(null),
      prefixes: [`Netfilter:${APP_VERSION}`]
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
        prefixes: ['LoadConfig']
      });
      const fse = require('fs-extra');

      fse.readFile(context.usageArgs.configurationFilePath)
        .then(data => {
          const yamlParser = require('js-yaml');

          const config = yamlParser.safeLoad(data);
          context.rawConfiguration = config;
        })
        .then(() => {
          return new Promise((resolve, reject) => {
            const schema = require('./generic-main-config-schema').configurationSchema;

            Joi.validate(context.rawConfiguration, schema, (error, configuration) => {
              if (error) {
                logger.error(`Invalid configuration: ${error.message}\n${error.stack}`);
                return reject(error);
              }
              context.configuration = configuration;
              resolve();
            });
          });
        })
        .then(() => {
          // Check if configuration exists
          return new Promise((resolve, reject) => {
            const configurationId = context.usageArgs.configurationId;

            const configurationItem = _.find(context.configuration.configurations, {
              id: configurationId
            });

            if (!configurationItem) {
              logger.error(`Cannot find the configuration id ${configurationId}`);
              return reject(new Error(`Cannot find the configuration item ${configurationId}`));
            }

            context.configurationItem = configurationItem;

            // Search the job
            const jobName = context.usageArgs.jobName;
            const configurationJob = _.find(context.configurationItem.jobs, {
              name: jobName
            });

            if (!configurationJob) {
              logger.error(`Cannot find the configuration job ${jobName}`);
              return reject(new Error(`Cannot find the configuration job ${jobName}`));
            }

            context.configurationJob = configurationJob;
            context.jobConfiguration = context.configurationJob.configuration;
            resolve();
          });
        })
        .then(resolve)
        .catch(reject);
    });
  })
  .then(() => {
    return new Promise((resolve, reject) => {
      const context = applicationWorkflow.context;
      const logger = context.logger.of({
        prefixes: ['CreateJobInstance']
      });

      let jobModule = undefined;
      try {
        jobModule = require(`./../jobs/${context.configurationJob.name}`);
      } catch (error) {
        logger.error("Cannot require the job %s.\n%s\n%s", context.configurationJob.name, error.message, error.stack);
        return reject(new commonErrors.NotFoundError(`Job ${context.configurationJob.name} not found`));
      }

      context.jobInstance = new jobModule.Job();
      context.jobInstance.initialize({})
        .then(() => {
          logger.debug("Job '%s' initialized", context.configurationJob.name);
          return resolve();
        })
        .catch(error => {
          logger.error("Initialization job %s failed.\n%s\n%s", context.configurationJob.name, error.message, error.stack);
          return reject(error);
        });
    });
  })
  .then(() => {
    const context = applicationWorkflow.context;
    const logger = context.logger.of({
      prefixes: ['ExecuteJob']
    });

    context.jobCommand = {
      type: context.usageArgs.action
    };

    return context.jobInstance.execute(context);
  })
  .then(executionResponse => {
    const context = applicationWorkflow.context;
    const logger = context.logger.of({
      prefixes: ['HandleExecutionResponse']
    });

    context.jobResponse = executionResponse;
    logger.debug("Execution of '%s' done", context.configurationJob.name);
  })
  .then(() => {
    return new Promise(resolve => {
      const context = applicationWorkflow.context;
      const logger = context.logger.of({
        prefixes: ['Print']
      });

      if (context.usageArgs.printRules !== true) {
        return;
      }

      let data = "--------------------\n";
      data += "--------------------\n";
      _.each(context.jobResponse.securityCommands, command => {
        switch (command.type) {
          case 'iptables-4':
            data += 'iptables ';
            break;
          case 'ipset':
            data += 'ipset ';
            break;
          default:
            return;
        }

        data += `${command.value}\n`;
      });
      data += "--------------------\n";
      data += "--------------------\n";
      process.stdout.write(data);
      resolve();
    });
  })
  .then(() => {
    return new Promise((resolve, reject) => {
      const context = applicationWorkflow.context;
      const logger = context.logger.of({
        prefixes: ['Apply']
      });

      if (context.usageArgs.apply !== true) {
        return;
      }

      let shFileData = "#! /bin/sh\n\n";
      _.each(context.jobResponse.securityCommands, command => {
        switch (command.type) {
          case 'iptables-4':
            shFileData += 'iptables ';
            break;
          case 'ipset':
            shFileData += 'ipset ';
            break;
          default:
            return;
        }

        shFileData += `${command.value}\n`;
      });

      const generateUuid = require('uuid/v4'),
        fse = require('fs-extra');
      const temporaryFilePath = '/tmp/netfilter-apply-' + Date.now() + '-' + generateUuid() + '.sh';

      const removeTemporaryFile = () => {
        logger.info(`Remove temporary file ${temporaryFilePath}`);
        fse.pathExists(temporaryFilePath)
          .then(exists => {
            if (exists) {
              return fse.remove(temporaryFilePath);
            }
          })
          .then(() => {
            logger.debug(`Temporary file ${temporaryFilePath} removed`);
          })
          .catch(error => {
            logger.error(`Failed to remove temporary file ${temporaryFilePath}: ${error.message}\n${error.stack}`);
          });
      };


      logger.info(`Write temporary file ${temporaryFilePath}`);
      return fse.outputFile(temporaryFilePath, shFileData, {
        mode: 0o740
      })
        .then(() => {
          logger.info(`Execute temporary file ${temporaryFilePath}`);
          return new Promise((resolve, reject) => {
            const child_process = require('child_process');

            child_process.exec(temporaryFilePath, function (error, stdout, stderr) {
              if (error) {
                logger.error(`Error while executing ${temporaryFilePath}: ${error.message}\n${error.stack}`);
                logger.error(`---- STDOUT BEGIN ----`);
                logger.error(stdout);
                logger.error(`---- STDOUT END ----`);
                logger.error(`---- STDERR BEGIN ----`);
                logger.error(stderr);
                logger.error(`---- STDERR END ----`);
                return reject(error);
              }

              logger.info(`Execution of ${temporaryFilePath} done with success`);
              logger.debug(`---- STDOUT BEGIN ----`);
              logger.debug(stdout);
              logger.debug(`---- STDOUT END ----`);
              logger.debug(`---- STDERR BEGIN ----`);
              logger.debug(stderr);
              logger.debug(`---- STDERR END ----`);
              return resolve();
            });
          });

        })
        .then(() => {
          removeTemporaryFile();
          resolve();
        })
        .catch(error => {
          removeTemporaryFile();
          reject(error);
        });
    });
  })
  .catch(error => {
    process.stderr.write(`Failed to process: ${error.message}\n${error.stack}\n`);
    process.exit(1);
  });
