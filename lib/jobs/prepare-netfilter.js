const SimpleInitializableObject = require('js-zrim-core').SimpleInitializableObject,
  _ = require('lodash'),
  Joi = require('joi'),
  jsErrors = require('js-zrim-errors'),
  commonErrors = jsErrors.common;


/**
 * Job to initialize netfilter for our purpose
 * @implements {SimpleInitializableObject}
 * @constructor
 */
function PrepareNetfilterJob() {
  if (!(this instanceof PrepareNetfilterJob)) {
    return new (Function.prototype.bind.apply(PrepareNetfilterJob, Array.prototype.concat.apply([null], arguments)))();
  }

  SimpleInitializableObject.apply(this, arguments);
}

SimpleInitializableObject._applyPrototypeTo(PrepareNetfilterJob);

/**
 * Execute the job
 * @param {BaseJob~ExecutionContext} context the context
 * @return {Promise} {@link BaseJob~ExecutionOnResolve} on resolve
 */
PrepareNetfilterJob.prototype.execute = function (context) {
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
      steps.push(availableSteps.generateVitalAccessChain);
      steps.push(availableSteps.generateBlockNetworkChain);
      steps.push(availableSteps.generateServiceAccessChain);
      steps.push(availableSteps.generateTrustedNetworkChain);
      steps.push(availableSteps.generateRootAccessChains);
    } else if (context.jobCommand.type.toLowerCase() === 'uninstall') {
      steps.push(availableSteps.generateRootAccessChains);
      steps.push(availableSteps.generateTrustedNetworkChain);
      steps.push(availableSteps.generateServiceAccessChain);
      steps.push(availableSteps.generateBlockNetworkChain);
      steps.push(availableSteps.generateVitalAccessChain);
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

/**
 * Make this string command as a {@link SecurityCommand} iptables ipv4
 * @param {string} command The command to make
 * @return {SecurityCommand} The command created
 * @private
 */
PrepareNetfilterJob.prototype._asIptables4Command = function (command) {
  return {
    type: 'iptables-4',
    value: command
  };
};

/**
 * Make this string command as a {@link SecurityCommand} ipset
 * @param {string} command The command to make
 * @return {SecurityCommand} The command created
 * @private
 */
PrepareNetfilterJob.prototype._asIpSetCommand = function (command) {
  return {
    type: 'ipset',
    value: command
  };
};


PrepareNetfilterJob.prototype.execute.Steps = {
  /**
   * Validate the job configuration
   * @param {BaseJob~ExecutionContext} context the context
   * @return {Promise}
   */
  validateConfiguration: function (context) {
    return new Promise((resolve, reject) => {
      const schema = Joi.object().keys({
        network: Joi.object().keys({
          trustedItems: Joi.array().items(
            Joi.object().keys({
              value: Joi.string().ip({
                cidr: 'required'
              }).required(),
              description: Joi.string()
            }).unknown()
          ),
          primaryInterfaces: Joi.array().items(
            Joi.object().keys({
              name: Joi.string().required(),
              networks: Joi.array().items(
                Joi.object().keys({
                  value: Joi.string().ip({
                    cidr: 'required'
                  }).required(),
                  description: Joi.string()
                }).unknown().required()
              ).required(),
              rules: Joi.object().keys({
                input: Joi.object().keys({
                  defaultAction: Joi.string().required()
                }).unknown().required(),
                output: Joi.object().keys({
                  defaultAction: Joi.string().required()
                }).unknown().required()
              }).unknown().required()
            }).unknown().required()
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
  },
  /**
   * Generate the vital access chains
   * @param {BaseJob~ExecutionContext} context the context
   * @return {Promise}
   */
  generateVitalAccessChain: function (context) {
    return new Promise(resolve => {
      const installCommands = [],
        unInstallCommands = [];

      const logger = context.logger.of({
        prefixes: ['generateVitalAccessChain']
      });

      const chainName = "vital_access_0";

      // Clean up & create
      installCommands.push(this._asIptables4Command(`-N IN_${chainName}`));
      unInstallCommands.push(this._asIptables4Command(`-F IN_${chainName}`));
      unInstallCommands.push(this._asIptables4Command(`-X IN_${chainName}`));

      installCommands.push(this._asIptables4Command(`-N OUT_${chainName}`));
      unInstallCommands.push(this._asIptables4Command(`-F OUT_${chainName}`));
      unInstallCommands.push(this._asIptables4Command(`-X OUT_${chainName}`));

      const primaryInterfaces = context.jobConfiguration.network.primaryInterfaces;
      _.each(primaryInterfaces, primaryInterface => {

        logger.info("Adding DHCP");
        installCommands.push(this._asIptables4Command(`-A IN_${chainName} --in-interface ${primaryInterface.name} -p udp --dport 67:68 --sport 67:68 -j ACCEPT`));
        installCommands.push(this._asIptables4Command(`-A OUT_${chainName} --out-interface ${primaryInterface.name} -p udp --dport 67:68 --sport 67:68 -j ACCEPT`));

        logger.info("Adding dns client");
        // UDP
        installCommands.push(this._asIptables4Command(`-A OUT_${chainName} --out-interface ${primaryInterface.name} -p udp --sport 1024:65535 --dport 53 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT`));
        installCommands.push(this._asIptables4Command(`-A IN_${chainName} --in-interface ${primaryInterface.name} -p udp --sport 53 --dport 1024:65535 -m state --state ESTABLISHED,RELATED -j ACCEPT`));
        // TCP
        installCommands.push(this._asIptables4Command(`-A OUT_${chainName} --out-interface ${primaryInterface.name} -p tcp --sport 1024:65535 --dport 53 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT`));
        installCommands.push(this._asIptables4Command(`-A IN_${chainName} --in-interface ${primaryInterface.name} -p tcp --sport 53 --dport 1024:65535 -m state --state ESTABLISHED,RELATED -j ACCEPT`));

        logger.info("Adding icmp");
        installCommands.push(this._asIptables4Command(`-A OUT_${chainName} -p icmp --in-interface ${primaryInterface.name} -d 0.0.0.0/0 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT`));
        installCommands.push(this._asIptables4Command(`-A IN_${chainName} -p icmp --out-interface ${primaryInterface.name} -s 0.0.0.0/0 -m state --state ESTABLISHED,RELATED -j ACCEPT`));
        installCommands.push(this._asIptables4Command(`-A IN_${chainName} -p icmp --icmp-type 8 --in-interface ${primaryInterface.name} -s 0.0.0.0/0 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT`));
        installCommands.push(this._asIptables4Command(`-A OUT_${chainName} -p icmp --out-interface ${primaryInterface.name} -d 0.0.0.0/0 -m state --state ESTABLISHED,RELATED -j ACCEPT`));

        logger.info("Adding ntp");
        installCommands.push(this._asIptables4Command(`-A OUT_${chainName} --out-interface ${primaryInterface.name} -p udp --sport 1024:65535 --dport 123 -j ACCEPT`));
        installCommands.push(this._asIptables4Command(`-A IN_${chainName} --in-interface ${primaryInterface.name} -p udp --sport 123 --dport 1024:65535 -m state --state ESTABLISHED,RELATED -j ACCEPT`));

        logger.info("Adding root access");
        installCommands.push(this._asIptables4Command(`-A OUT_${chainName} --out-interface ${primaryInterface.name} -m owner --uid-owner 0 -j ACCEPT`));

        logger.info("Adding accept known packets");
        installCommands.push(this._asIptables4Command(`-A IN_${chainName} --in-interface ${primaryInterface.name} -m state --state ESTABLISHED,RELATED -j ACCEPT`));

        _.each(primaryInterface.networks, interfaceNetwork => {
          logger.info(`Adding lo for network ${interfaceNetwork.value}`);
          installCommands.push(this._asIptables4Command(`-A IN_${chainName} --in-interface lo -s ${interfaceNetwork.value} -d ${interfaceNetwork.value} -j ACCEPT`));
          installCommands.push(this._asIptables4Command(`-A IN_${chainName} --in-interface lo -s ${interfaceNetwork.value} -d 127.0.0.0/8 -j ACCEPT`));
          installCommands.push(this._asIptables4Command(`-A OUT_${chainName} --out-interface lo -s ${interfaceNetwork.value} -d ${interfaceNetwork.value} -j ACCEPT`));
          installCommands.push(this._asIptables4Command(`-A OUT_${chainName} --out-interface lo -s ${interfaceNetwork.value} -d 127.0.0.0/8 -j ACCEPT`));
        });
      });

      installCommands.push(this._asIptables4Command(`-A IN_${chainName} ! --in-interface lo -d 127.0.0.0/8 -j REJECT`));
      installCommands.push(this._asIptables4Command(`-A OUT_${chainName} --out-interface lo -d 127.0.0.0/8 -j ACCEPT`));

      logger.info("Last step RETURN");
      installCommands.push(this._asIptables4Command(`-A IN_${chainName} -j RETURN`));
      installCommands.push(this._asIptables4Command(`-A OUT_${chainName} -j RETURN`));

      context.commands.install = _.concat(context.commands.install, installCommands);
      context.commands.unInstall = _.concat(context.commands.unInstall, unInstallCommands);

      resolve();
    });
  },
  /**
   * Generate block chain access
   * @param {BaseJob~ExecutionContext} context the context
   * @return {Promise}
   */
  generateBlockNetworkChain: function (context) {
    return new Promise(resolve => {
      const installCommands = [],
        unInstallCommands = [];

      const logger = context.logger.of({
        prefixes: ['blockNetworkChain']
      });

      const chainName = "block_access_0";

      logger.debug("Create the chain 'IN_%s'", chainName);
      installCommands.push(this._asIptables4Command(`-N IN_${chainName}`));
      unInstallCommands.push(this._asIptables4Command(`-F IN_${chainName}`));
      unInstallCommands.push(this._asIptables4Command(`-X IN_${chainName}`));

      logger.debug("Add create ipset net '%s'", 'block_net');
      installCommands.push(this._asIpSetCommand(`-! create block_net hash:net`));
      unInstallCommands.push(this._asIpSetCommand(`-! destroy block_net`));

      logger.debug("Configure chain 'IN_%s'", chainName);
      installCommands.push(this._asIptables4Command(`-A IN_${chainName} -j DROP`));

      context.commands.install = _.concat(context.commands.install, installCommands);
      context.commands.unInstall = _.concat(context.commands.unInstall, unInstallCommands);

      resolve();
    });
  },
  /**
   * Generate block chain access
   * @param {BaseJob~ExecutionContext} context the context
   * @return {Promise}
   */
  generateServiceAccessChain: function (context) {
    return new Promise(resolve => {
      const installCommands = [],
        unInstallCommands = [];

      const logger = context.logger.of({
        prefixes: ['serviceAccessChain']
      });

      const chainName = "services_access_0";

      logger.debug("Create the chain 'IN_%s'", chainName);
      installCommands.push(this._asIptables4Command(`-N IN_${chainName}`));
      unInstallCommands.push(this._asIptables4Command(`-F IN_${chainName}`));
      unInstallCommands.push(this._asIptables4Command(`-X IN_${chainName}`));
      installCommands.push(this._asIptables4Command(`-A IN_${chainName} -j RETURN`));

      logger.debug("Create the chain 'OUT_%s'", chainName);
      installCommands.push(this._asIptables4Command(`-N OUT_${chainName}`));
      unInstallCommands.push(this._asIptables4Command(`-F OUT_${chainName}`));
      unInstallCommands.push(this._asIptables4Command(`-X OUT_${chainName}`));
      installCommands.push(this._asIptables4Command(`-A OUT_${chainName} -j RETURN`));

      context.commands.install = _.concat(context.commands.install, installCommands);
      context.commands.unInstall = _.concat(context.commands.unInstall, unInstallCommands);

      resolve();
    });
  },
  /**
   * Generate trusted chain access
   * @param {BaseJob~ExecutionContext} context the context
   * @return {Promise}
   */
  generateTrustedNetworkChain: function (context) {
    return new Promise(resolve => {
      const installCommands = [],
        unInstallCommands = [];

      const logger = context.logger.of({
        prefixes: ['trustedNetworkChain']
      });

      const chainName = "trusted_access_0";

      const globalTrustedNetworks = _.get(context, 'configuration.global.network.trustedItems', []),
        jobTrustedNetworks = _.get(context, 'jobConfiguration.network.trustedItems', []),
        trustedNetworks = _.concat([], globalTrustedNetworks, jobTrustedNetworks);

      logger.debug("Add create ipset net '%s'", 'trusted_net');
      installCommands.push(this._asIpSetCommand(`-! create trusted_net hash:net`));

      _.each(trustedNetworks, network => {
        logger.debug("Add trusted network '%s'", network.value);
        installCommands.push(this._asIpSetCommand(`-! add trusted_net ${network.value}`));
      });

      logger.debug("Create the chain 'IN_%s'", chainName);
      installCommands.push(this._asIptables4Command(`-N IN_${chainName}`));
      unInstallCommands.push(this._asIptables4Command(`-F IN_${chainName}`));
      unInstallCommands.push(this._asIptables4Command(`-X IN_${chainName}`));
      installCommands.push(this._asIptables4Command(`-A IN_${chainName} -m set --match-set trusted_net src -j ACCEPT`));
      installCommands.push(this._asIptables4Command(`-A IN_${chainName} -j RETURN`));

      logger.debug("Create the chain 'OUT_%s'", chainName);
      installCommands.push(this._asIptables4Command(`-N OUT_${chainName}`));
      unInstallCommands.push(this._asIptables4Command(`-F OUT_${chainName}`));
      unInstallCommands.push(this._asIptables4Command(`-X OUT_${chainName}`));
      installCommands.push(this._asIptables4Command(`-A OUT_${chainName} -m set --match-set trusted_net dst -j ACCEPT`));
      installCommands.push(this._asIptables4Command(`-A OUT_${chainName} -j RETURN`));

      // Delete set
      unInstallCommands.push(this._asIpSetCommand(`-! destroy trusted_net`));

      context.commands.install = _.concat(context.commands.install, installCommands);
      context.commands.unInstall = _.concat(context.commands.unInstall, unInstallCommands);

      resolve();
    });
  },
  /**
   * Generate root chain access
   * @param {BaseJob~ExecutionContext} context the context
   * @return {Promise}
   */
  generateRootAccessChains: function (context) {
    return new Promise(resolve => {
      const installCommands = [],
        unInstallCommands = [];

      const logger = context.logger.of({
        prefixes: ['rootAccessChains']
      });

      installCommands.push(this._asIptables4Command(`-I INPUT 1 -j IN_trusted_access_0`));
      unInstallCommands.push(this._asIptables4Command(`-D INPUT -j IN_trusted_access_0`));

      installCommands.push(this._asIptables4Command(`-I INPUT 2 -j IN_vital_access_0`));
      unInstallCommands.push(this._asIptables4Command(`-D INPUT -j IN_vital_access_0`));

      installCommands.push(this._asIptables4Command(`-I INPUT 3 -m set --match-set block_net src -j IN_block_access_0`)); // Chain for block input
      unInstallCommands.push(this._asIptables4Command(`-D INPUT -m set --match-set block_net src -j IN_block_access_0`));

      installCommands.push(this._asIptables4Command(`-I INPUT 4 -j IN_services_access_0`));
      unInstallCommands.push(this._asIptables4Command(`-D INPUT -j IN_services_access_0`));

      const primaryInterfaces = context.jobConfiguration.network.primaryInterfaces;
      _.each(primaryInterfaces, primaryInterface => {
        installCommands.push(this._asIptables4Command(`-A INPUT --in-interface ${primaryInterface.name} -j ${primaryInterface.rules.input.defaultAction}`));
        unInstallCommands.push(this._asIptables4Command(`-D INPUT --in-interface ${primaryInterface.name} -j ${primaryInterface.rules.input.defaultAction}`));
      });

      installCommands.push(this._asIptables4Command(`-I OUTPUT 1 -j OUT_trusted_access_0`));
      unInstallCommands.push(this._asIptables4Command(`-D OUTPUT -j OUT_trusted_access_0`));

      installCommands.push(this._asIptables4Command(`-I OUTPUT 2 -j OUT_vital_access_0`));
      unInstallCommands.push(this._asIptables4Command(`-D OUTPUT -j OUT_vital_access_0`));

      installCommands.push(this._asIptables4Command(`-I OUTPUT 3 -j OUT_services_access_0`));
      unInstallCommands.push(this._asIptables4Command(`-D OUTPUT -j OUT_services_access_0`));

      context.commands.install = _.concat(context.commands.install, installCommands);
      context.commands.unInstall = _.concat(context.commands.unInstall, unInstallCommands);

      resolve();
    });
  }
};

exports.PrepareNetfilterJob = module.exports.PrepareNetfilterJob = PrepareNetfilterJob;
exports.Job = module.exports.Job = PrepareNetfilterJob;
