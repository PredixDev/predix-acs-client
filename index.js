'use strict'
const request = require('request');
const url = require('url');
const uaa = require('predix-uaa-client');
const debug = require('debug')('predix-acs-client');

module.exports = (config) => {

    if(config) {
        config.renew_secs_before = config.renew_secs_before || 60;
    }

    // Throw exception if required options are missing
    let missingConfig = [];
    if(!config || !config.uaa || !config.uaa.uri) missingConfig.push('uaa.uri');
    if(!config || !config.uaa || !config.uaa.clientId) missingConfig.push('uaa.clientId');
    if(!config || !config.uaa || !config.uaa.clientSecret) missingConfig.push('uaa.clientSecret');
    if(!config || !config.acsUri) missingConfig.push('acsUri');
    if(!config || !config.zoneId) missingConfig.push('zoneId');

    if(missingConfig.length > 0) {
        const msg = 'Required configuration is missing: ' + missingConfig.join();
        debug(msg);
        throw new Error(msg);
    }

    let acs_utils = {};

    // This will fetch and cache an access token for the provided UAA client using the credentials
    // that were provided at configuration time.
    // If there is already a token which has not expired, that will be returned immediately

    /**
     * This will fetch and cache an access token for the provided UAA client using the credentials
     * that were provided at configuration time.
     * If there is already a token which has not expired, that will be returned immediately
     *
     * @returns {promise} - A promise to provide a token.
     *                      Resolves with the token if successful (or already available).
     *                      Rejected with an error if an error occurs.
     */
    acs_utils._getToken = () => {
        return new Promise((resolve, reject) => {
            uaa.getToken(config.uaa.uri, config.uaa.clientId, config.uaa.clientSecret).then((token) => {
                resolve(token.access_token);
            }).catch((err) => {
                reject(err);
            });
        });
    }

     /**
     * Checks that the provided user is allowed to perform the action described by the request
     * This request is decoupled from the request path, allowing for an alternative description of resources
     *
     * @param {object} abacRequest - The Attributes Based Access Control request.
     *                       Required properties: subject, resource, action
     * @returns {promise} - A promise to authorize the user.
     *                      Resolves with the user and resource attributes.
     *                      Rejected if not authorized, or an error occurs.
     */
    acs_utils.isAuthorizedFor = (abacRequest) => {
        return new Promise((resolve, reject) => {
            if (abacRequest === null || !abacRequest) {
                return reject('Parameter: \'abacRequest\' may not be null or undefined.');
            }
            if (!abacRequest.action || !abacRequest.resourceIdentifier || !abacRequest.subjectIdentifier) {
                return reject('Parameter: \'abacRequest\' must contain the properties: action, resourceIdentifier, and subjectIdentifier');
            }

            // Ensure we have a valid token to talk to ACS
            acs_utils._getToken().then((token) => {
                // Formulate the request object
                const options = {
                    url: config.acsUri + '/v1/policy-evaluation',
                    headers: {
                        'cache-control': 'no-cache',
                        'content-type': 'application/json',
                        'Predix-Zone-Id': config.zoneId
                    },
                    auth: {
                        bearer: token
                    },
                    json: true,
                    body: abacRequest
                };

                // Call ACS
                request.post(options, (err, resp, data) => {
                    const statusCode = (resp) ? resp.statusCode : 502;
                    if(err || statusCode !== 200) {
                        err = err || 'Error getting verdict: ' + statusCode;
                        debug('Error getting verdict with request', options, err);
                        reject(err);
                    } else {
                        // Check the 'effect' property
                        if(data.effect === 'PERMIT') {
                            resolve(data);
                        } else {
                            debug('Not Authorized', options.body, data);
                            reject(data);
                        }
                    }
                });
            }).catch((err) => {
                reject(err);
            });
        });
    }

    /**
     * Checks that the provided user is allowed to perform the action described by the request
     *
     * @param {object} req - The request.  Compatible with expressjs request.
     *                       Required properties: method, path
     * @param {string} username - The subject (or username) of the requester.
     * @returns {promise} - A promise to authorize the user.
     *                      Resolves with the user and resource attributes.
     *                      Rejected if not authorized, or an error occurs.
     */
    acs_utils.isAuthorized = (req, username, scopes) => {
        const abacRequest = {
            action: req.method,
            resourceIdentifier: req.path,
            subjectIdentifier: username
        };

        // constructing scope-based subject attributes
        if (scopes) {
          const userGroupsRegEx = config.userGroupsRegEx || 'g.*';
          const attributes = scopes.filter(scope => scope.match(userGroupsRegEx))
          .map(scope => ({
            issuer: 'UAA',
            name: 'group',
            value: scope
          }));
          if (attributes.length > 0) {
            abacRequest.subjectAttributes = attributes;
          }
        }
        return acs_utils.isAuthorizedFor(abacRequest);
    }

    /**
     * Get subject of provided user from acs
     *
     * @param {string} username - The subject (or username) of the requester.
     * @returns {promise} - A promise to authorize the user.
     *                      Resolves with the user and resource attributes.
     *                      Rejected if not authorized, or an error occurs.
     */
    acs_utils.getSubjectAttributes = (subjectIdentifier) => {
        return new Promise((resolve, reject) => {
            // Ensure we have a valid token to talk to ACS
            acs_utils._getToken().then((token) => {
                // Formulate the request object
                const options = {
                    url: config.acsUri + '/v1/subject/' + subjectIdentifier,
                    headers: {
                        'cache-control': 'no-cache',
                        'content-type': 'application/json',
                        'Predix-Zone-Id': config.zoneId
                    },
                    auth: {
                        bearer: token
                    },
                    json: true
                };

                // Call ACS
                request.get(options, (err, resp, data) => {
                    const statusCode = (resp) ? resp.statusCode : 502;
                    if(err || statusCode !== 200) {
                        err = err || 'Error getting subject: ' + statusCode;
                        debug('Error getting subject with request', options, err);
                        reject(err);
                    } else {
                        resolve(data);
                    }
                });
            }).catch((err) => {
                reject(err);
            });
        });
    }

    return acs_utils;
}
