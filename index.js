'use strict'
const request = require('request');
const url = require('url');
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
    let access_token = null;

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
        // URL for the token is <UAA_Server>/oauth/token
        return new Promise((resolve, reject) => {

            let alreadyResolved = false;
            const now = Date.now();

            // Check the current token
            if(access_token && access_token.expire_time > now) {
                // Already have it.
                resolve(access_token.token);
                alreadyResolved = true;
            }

            // Should we get a new token?
            // If we don't have one, or ours is expiring soon, then yes!
            if(!access_token || access_token.renew_time < now) {
                // Yep, don't have one, or this one will expire soon.
                debug('Fetching new token');

                const options = {
                    url: config.uaa.uri,
                    headers: {
                        'cache-control': 'no-cache',
                        'content-type': 'application/x-www-form-urlencoded'
                    },
                    auth: {
                        username: config.uaa.clientId,
                        password: config.uaa.clientSecret
                    },
                    form: {
                        grant_type: 'client_credentials'
                    }
                };

                request.post(options, (err, resp, body) => {
                    const statusCode = (resp) ? resp.statusCode : 502;
                    if(err || statusCode !== 200) {
                        err = err || 'Error getting token: ' + statusCode;
                        debug('Error getting token from', options.url, err);
                        if(!alreadyResolved) {
                            reject(err);
                        }
                    } else {
                        debug('Fetched new token');
                        const data = JSON.parse(body);
                        // Extract the token and expires duration
                        const newToken = {
                            token: data.access_token,
                            expire_time: now + (data.expires_in * 1000),
                            renew_time: now + ((data.expires_in - config.renew_secs_before) * 1000)
                        };
                        access_token = newToken;
                        if(!alreadyResolved) {
                            resolve(access_token.token);
                        }
                    }
                });
            }
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
    acs_utils.isAuthorized = (req, username) => {
        return new Promise((resolve, reject) => {
            // Ensure we have a valid token to talk to ACS
            acs_utils._getToken().then((token) => {
                // Formulate the request object
                const options = {
                    url: config.acsUri,
                    headers: {
                        'cache-control': 'no-cache',
                        'content-type': 'application/x-www-form-urlencoded'
                    },
                    auth: {
                        bearer: token,
                    },
                    body: {
                        action: req.method,
                        resourceIdentifier: req.path,
                        subjectIdentifier: username
                    }
                };

                // Call ACS
                request.post(options, (err, resp, body) => {
                    const statusCode = (resp) ? resp.statusCode : 502;
                    if(err || statusCode !== 200) {
                        err = err || 'Error getting verdict: ' + statusCode;
                        debug('Error getting verdict from', options.url, err);
                        reject(err);
                    } else {
                        const data = JSON.parse(body);
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

    return acs_utils;
}

