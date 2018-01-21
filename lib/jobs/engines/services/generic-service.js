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
function GenericServiceJob() {
  if (!(this instanceof GenericServiceJob)) {
    return new (Function.prototype.bind.apply(GenericServiceJob, Array.prototype.concat.apply([null], arguments)))();
  }

  SimpleInitializableObject.apply(this, arguments);
}

SimpleInitializableObject._applyPrototypeTo(GenericServiceJob);

/**
 * Execute the job
 * @param {BaseJob~ExecutionContext} context the context
 * @return {Promise} {@link BaseJob~ExecutionOnResolve} on resolve
 */
GenericServiceJob.prototype.execute = function (context) {
  return new Promise((resolve, reject) => {
    const logger = context.logger.of({
      prefixes: ['main']
    });

    _.set(context, 'commands.install', []);
    _.set(context, 'commands.unInstall', []);

    const steps = [
      this._validateConfiguration,
      this._generateRules
    ];
    if (['install', 'uninstall'].indexOf(context.jobCommand.type.toLowerCase()) === -1) {
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

/**
 * Make this string command as a {@link SecurityCommand} iptables ipv4
 * @param {string} command The command to make
 * @return {SecurityCommand} The command created
 * @private
 */
GenericServiceJob.prototype._asIptables4Command = function (command) {
  return {
    type: 'iptables-4',
    value: command
  };
};

/**
 * Validate the job configuration
 * @param {BaseJob~ExecutionContext} context the context
 * @return {Promise}
 */
GenericServiceJob.prototype._validateConfiguration = function (context) {
  return new Promise((resolve, reject) => {
    const schema = Joi.object().keys({
      chainName: Joi.string(),
      network: Joi.object().keys({
        items: Joi.array().items(
          Joi.object().keys({
            portNumber: Joi.number().required(),
            sourceNetworks: Joi.array().items(
              Joi.string().ip({
                cidr: 'optional'
              })
            ).allow(null),
            protocol: Joi.string().required(),
            destinationNetwork: Joi.string().ip({
              cidr: 'optional'
            }).allow(null)
          }).unknown()
        ).required()
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
};

/**
 * Returns the chain name used for the service
 * @return {string} The chain name
 * @private
 */
GenericServiceJob.prototype._getServiceChainName = function () {
  return 'genericServiceName';
};

/**
 * Generate the rules
 * @param {BaseJob~ExecutionContext} context the context
 * @return {Promise}
 */
GenericServiceJob.prototype._generateRules = function (context) {
  return new Promise(resolve => {
    const installCommands = [],
      unInstallCommands = [];

    const logger = context.logger.of({
      prefixes: ['generateVitalAccessChain']
    });

    const chainName = context.configurationJob.chainName || this._getServiceChainName();

    // Remove chains
    unInstallCommands.push(this._asIptables4Command(`-D IN_services_access_0 -j IN_${chainName}`));
    unInstallCommands.push(this._asIptables4Command(`-D OUT_services_access_0 -j OUT_${chainName}`));

    // Clean up & create
    installCommands.push(this._asIptables4Command(`-N IN_${chainName}`));
    unInstallCommands.push(this._asIptables4Command(`-F IN_${chainName}`));
    unInstallCommands.push(this._asIptables4Command(`-X IN_${chainName}`));

    installCommands.push(this._asIptables4Command(`-N OUT_${chainName}`));
    unInstallCommands.push(this._asIptables4Command(`-F OUT_${chainName}`));
    unInstallCommands.push(this._asIptables4Command(`-X OUT_${chainName}`));

    const networkItems = context.jobConfiguration.network.items || [];
    _.each(networkItems, item => {
      const {portNumber, protocol, destinationNetwork} = item;
      const sourceNetworks = item.sourceNetworks || [];

      const destinationNetworkPart = _.isNil(destinationNetwork) ? '' : ` -d ${destinationNetwork}`,
        protocolPortNumberPart = ` -p ${protocol} --sport 1024:65535 --dport ${portNumber}`;

      if (sourceNetworks.length === 0) {
        installCommands.push(this._asIptables4Command(`-A IN_${chainName} ${destinationNetworkPart}${protocolPortNumberPart} -j ACCEPT`));
      } else {
        _.each(sourceNetworks, n => {
          installCommands.push(this._asIptables4Command(`-A IN_${chainName} -s ${n} ${destinationNetworkPart}${protocolPortNumberPart} -j ACCEPT`));
        });
      }
    });

    logger.info("Last step RETURN");
    installCommands.push(this._asIptables4Command(`-A IN_${chainName} -j RETURN`));
    installCommands.push(this._asIptables4Command(`-A OUT_${chainName} -j RETURN`));

    // Add the chain to the service access
    logger.info(`Install chain ${chainName} to the INPUT/OUTPUT`);
    installCommands.push(this._asIptables4Command(`-I IN_services_access_0 1 -j IN_${chainName}`));
    installCommands.push(this._asIptables4Command(`-I OUT_services_access_0 1 -j OUT_${chainName}`));

    context.commands.install = _.concat(context.commands.install, installCommands);
    context.commands.unInstall = _.concat(context.commands.unInstall, unInstallCommands);

    resolve();
  });
};

exports.GenericServiceJob = module.exports.GenericServiceJob = GenericServiceJob;
exports.Job = module.exports.Job = GenericServiceJob;
