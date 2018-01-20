

/**
 * Context given to the job for execution
 * @typedef {Object} BaseJob~ExecutionContext
 * @property {Logger} logger The logger to use
 * @property {JobCommand} jobCommand The job command
 * @property {Object} configuration The whole configuration
 * @property {Object} jobConfiguration The job configuration
 */

/**
 * Contains information about the command to execute
 * @typedef {Object} JobCommand
 * @property {string} type The command type
 */

/**
 * @typedef {Object} SecurityCommand
 * @property {string} type The command type
 * @property {string} value The command value
 */

/**
 * Response returned by the execution
 * @typedef {Object} BaseJob~ExecutionOnResolve
 * @property {SecurityCommand[]} securityCommands The commands
 */
