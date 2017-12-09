const Joi = require('joi');

exports.configurationSchema = module.exports.configurationSchema = Joi.object().keys({
  version: Joi.string().required(),
  fileVersion: Joi.string().required(),
  global: Joi.object().keys({
    network: Joi.object().keys({
      trustedItems: Joi.array().items(
        Joi.object().keys({
          value: Joi.string().ip({
            cidr: 'required'
          }).required(),
          description: Joi.string()
        }).unknown()
      )
    }).unknown()
  }).unknown(),
  configurations: Joi.array().items(
    Joi.object().keys({
      id: Joi.string().required(),
      jobs: Joi.array().items(
        Joi.object().keys({
          name: Joi.string().required(),
          configuration: Joi.object().unknown().required()
        }).unknown()
      ).required()
    }).unknown()
  ).required()
}).unknown().required();
