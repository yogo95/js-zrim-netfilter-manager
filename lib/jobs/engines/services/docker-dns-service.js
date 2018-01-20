const SimpleInitializableObject = require('js-zrim-core').SimpleInitializableObject,
  _ = require('lodash'),
  Joi = require('joi'),
  jsErrors = require('js-zrim-errors'),
  commonErrors = jsErrors.common;

/**
 * Job to initialize a dns service/server from a docker container
 *
 * To make the dns working, we expose a special port and want to forward from a specific ip.
 * To do so, we are using nat and postrouting
 *
 * @see https://www.systutorials.com/816/port-forwarding-using-iptables/
 * @implements {SimpleInitializableObject}
 * @constructor
 */
function DockerDnsServiceJob() {
  if (!(this instanceof DockerDnsServiceJob)) {
    return new (Function.prototype.bind.apply(DockerDnsServiceJob, Array.prototype.concat.apply([null], arguments)))();
  }

  SimpleInitializableObject.apply(this, arguments);
}

SimpleInitializableObject._applyPrototypeTo(DockerDnsServiceJob);

/**
 * Execute the job
 * @param {BaseJob~ExecutionContext} context the context
 * @return {Promise} {@link BaseJob~ExecutionOnResolve} on resolve
 */
DockerDnsServiceJob.prototype.execute = function (context) {
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
DockerDnsServiceJob.prototype._asIptables4Command = function (command) {
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
DockerDnsServiceJob.prototype._validateConfiguration = function (context) {
  return new Promise((resolve, reject) => {
    const schema = Joi.object().keys({
      chainName: Joi.string(),
      network: Joi.object().keys({
        items: Joi.array().items(
          Joi.object().keys({
            sourcePortNumber: Joi.number().default(53),
            sourceLinkName: Joi.string().required(),
            sourceIpAddress: Joi.string().ip({
              cidr: 'forbidden'
            }).required(),
            destinationPortNumber: Joi.number().required(),
            destinationIpAddress: Joi.string().ip({
              cidr: 'forbidden'
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
DockerDnsServiceJob.prototype._getServiceChainName = function () {
  return 'dockerDnsService';
};

/**
 * Generate the rules
 * @param {BaseJob~ExecutionContext} context the context
 * @return {Promise}
 */
DockerDnsServiceJob.prototype._generateRules = function (context) {
  return new Promise(resolve => {
    const installCommands = [],
      unInstallCommands = [];

    const logger = context.logger.of({
      prefixes: ['dockerDnsService']
    });

    // iptables -A PREROUTING -t nat -i eth0 -p tcp --dport 80 -j DNAT --to 192.168.1.2:8080
    // iptables -A FORWARD -p tcp -d 192.168.1.2 --dport 8080 -j ACCEPT

    const chainName = context.jobConfiguration.chainName || this._getServiceChainName();

    // Remove chains
    unInstallCommands.push(this._asIptables4Command(`-D IN_services_access_0 -j IN_dns_${chainName}`));
    unInstallCommands.push(this._asIptables4Command(`-D OUT_services_access_0 -j OUT_dns_${chainName}`));

    // Clean up & create
    installCommands.push(this._asIptables4Command(`-N IN_dns_${chainName}`));
    unInstallCommands.push(this._asIptables4Command(`-F IN_dns_${chainName}`));
    unInstallCommands.push(this._asIptables4Command(`-X IN_dns_${chainName}`));

    installCommands.push(this._asIptables4Command(`-N OUT_dns_${chainName}`));
    unInstallCommands.push(this._asIptables4Command(`-F OUT_dns_${chainName}`));
    unInstallCommands.push(this._asIptables4Command(`-X OUT_dns_${chainName}`));

    const networkItems = context.jobConfiguration.network.items || [];
    _.each(networkItems, item => {
      const {sourceIpAddress, sourcePortNumber, sourceLinkName, destinationPortNumber, destinationIpAddress} = item;

      // Remove nat
      unInstallCommands.push(this._asIptables4Command(`-D PREROUTING -t nat -i ${sourceLinkName} -p tcp -d ${sourceIpAddress} --dport ${sourcePortNumber} -j DNAT --to ${destinationIpAddress}:${destinationPortNumber}`));
      unInstallCommands.push(this._asIptables4Command(`-D PREROUTING -t nat -i ${sourceLinkName} -p udp -d ${sourceIpAddress} --dport ${sourcePortNumber} -j DNAT --to ${destinationIpAddress}:${destinationPortNumber}`));

      installCommands.push(this._asIptables4Command(`-I PREROUTING 1 -t nat -i ${sourceLinkName} -p tcp -d ${sourceIpAddress} --dport ${sourcePortNumber} -j DNAT --to ${destinationIpAddress}:${destinationPortNumber}`));
      installCommands.push(this._asIptables4Command(`-I PREROUTING 1 -t nat -i ${sourceLinkName} -p udp -d ${sourceIpAddress} --dport ${sourcePortNumber} -j DNAT --to ${destinationIpAddress}:${destinationPortNumber}`));

      // Forward
      unInstallCommands.push(this._asIptables4Command(`-D FORWARD -p tcp -d ${destinationIpAddress} --dport ${destinationPortNumber} -j ACCEPT`));
      unInstallCommands.push(this._asIptables4Command(`-D FORWARD -p udp -d ${destinationIpAddress} --dport ${destinationPortNumber} -j ACCEPT`));

      installCommands.push(this._asIptables4Command(`-I FORWARD 1 -p tcp -d ${destinationIpAddress} --dport ${destinationPortNumber} -j ACCEPT`));
      installCommands.push(this._asIptables4Command(`-I FORWARD 1 -p udp -d ${destinationIpAddress} --dport ${destinationPortNumber} -j ACCEPT`));

      installCommands.push(this._asIptables4Command(`-A IN_dns_${chainName} -p tcp -d ${sourceIpAddress} --dport ${sourcePortNumber} -j ACCEPT`));
      installCommands.push(this._asIptables4Command(`-A IN_dns_${chainName} -p udp -d ${sourceIpAddress} --dport ${sourcePortNumber} -j ACCEPT`));
    });

    logger.info("Last step RETURN");
    installCommands.push(this._asIptables4Command(`-A IN_dns_${chainName} -j RETURN`));
    installCommands.push(this._asIptables4Command(`-A OUT_dns_${chainName} -j RETURN`));

    // Add the chain to the service access
    logger.info(`Install chain ${chainName} to the INPUT/OUTPUT`);
    installCommands.push(this._asIptables4Command(`-I IN_services_access_0 1 -j IN_dns_${chainName}`));
    installCommands.push(this._asIptables4Command(`-I OUT_services_access_0 1 -j OUT_dns_${chainName}`));

    context.commands.install = _.concat(context.commands.install, installCommands);
    context.commands.unInstall = _.concat(context.commands.unInstall, unInstallCommands);

    resolve();
  });
};

exports.DockerDnsServiceJob = module.exports.DockerDnsServiceJob = DockerDnsServiceJob;
exports.Job = module.exports.Job = DockerDnsServiceJob;
