const SimpleInitializableObject = require('js-zrim-core').SimpleInitializableObject,
  _ = require('lodash'),
  Joi = require('joi'),
  jsErrors = require('js-zrim-errors'),
  commonErrors = jsErrors.common;

/**
 * Job to initialize synchronize blacklist ips
 * @implements {SimpleInitializableObject}
 * @constructor
 */
function SynchronizeBlacklistIps() {
  if (!(this instanceof SynchronizeBlacklistIps)) {
    return new (Function.prototype.bind.apply(SynchronizeBlacklistIps, Array.prototype.concat.apply([null], arguments)))();
  }

  SimpleInitializableObject.apply(this, arguments);
}

SimpleInitializableObject._applyPrototypeTo(SynchronizeBlacklistIps);

/**
 * Execute the job
 * @param {BaseJob~ExecutionContext} context the context
 * @return {Promise} {@link BaseJob~ExecutionOnResolve} on resolve
 */
SynchronizeBlacklistIps.prototype.execute = function (context) {
  return new Promise((resolve, reject) => {
    const logger = context.logger.of({
      prefixes: ['main']
    });

    _.set(context, 'commands.install', []);
    _.set(context, 'commands.unInstall', []);

    const availableSteps = this.execute.Steps;
    const steps = [
      availableSteps.validateConfiguration
    ];
    if (context.jobCommand.type.toLowerCase() === 'install') {
      steps.push(availableSteps.fetchNetworks);
    } else if (context.jobCommand.type.toLowerCase() === 'uninstall') {
      // Ignore
      steps.push(availableSteps.fetchNetworks);
    } else {
      return reject(new commonErrors.IllegalArgumentError(`Invalid command ${context.jobCommand.type}`));
    }

    let workflowPromise = Promise.resolve({});
    _.each(steps, step => {
      workflowPromise = workflowPromise.then(() => step.call(this, context));
    });

    workflowPromise
      .then(() => {
        const response = {
          securityCommands: []
        };

        if (context.jobCommand.type === 'install') {
          response.securityCommands = context.commands.install;
        } else {
          response.securityCommands = context.commands.unInstall;
        }

        resolve(response);
      })
      .catch(error => {
        logger.error("Error while executing the workflow: %s\n%s", error.message, error.stack);
        reject(error);
      });
  });
};


SynchronizeBlacklistIps.prototype.execute.Steps = {
  /**
   * Validate the job configuration
   * @param {BaseJob~ExecutionContext} context the context
   * @return {Promise}
   */
  validateConfiguration: function (context) {
    return new Promise((resolve, reject) => {
      const schema = Joi.object().keys({
        database: Joi.object().keys({
          connectionString: Joi.string().uri({
            scheme: 'postgres'
          }).required()
        }).unknown().required()
      }).unknown().required();

      Joi.validate(context.jobConfiguration, schema, (error, configValidated) => {
        if (error) {
          return reject(new commonErrors.IllegalArgumentError(`Invalid configuration: ${error.message}`), error);
        }

        context.rawJobConfiguration = context.jobConfiguration;
        context.jobConfiguration = configValidated;
        resolve();
      });
    });
  },
  /**
   * Fetch the netowkr
   * @param {BaseJob~ExecutionContext} context the context
   * @return {Promise}
   */
  fetchNetworks: function (context) {
    return new Promise((resolve, reject) => {
      const logger = context.logger.of({
        prefixes: ['fetchNetworks']
      });

      const pgp = require('pg-promise')();
      const db = pgp(context.jobConfiguration.database.connectionString);

      db.query('SELECT value FROM security.blacklist_networks WHERE ip_version=4')
        .then(result => {
          const securityCommands = [];

          _.each(result, item => {
            securityCommands.push({
              type: 'ipset',
              value: `-! add block_net ${item.value}`
            });
          });

          db.$pool.end();

          _.set(context, 'commands.install', securityCommands);
          _.set(context, 'commands.unInstall', [{
            type: 'ipset',
            value: `flush block_net`
          }]);
          resolve();
        })
        .catch(error => {
          logger.error("Error while fetching: %s\n%s", error.message, error.stack);
          reject(error);
        });
    });
  }
};

exports.SynchronizeBlacklistIps = module.exports.SynchronizeBlacklistIps = SynchronizeBlacklistIps;
exports.Job = module.exports.Job = SynchronizeBlacklistIps;
