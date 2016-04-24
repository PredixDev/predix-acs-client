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
    acs_utils._getToken = () => {
        // URL for the token is <UAA_Server>/oauth/token
        return new Promise((resolve, reject) => {

            let alreadyResolved = false;
            const now = Date.now();

            // Check the current token
            if(access_token && access_token.expire_time > now) {
                // Already have it.
                debug('Existing token is OK');
                resolve(access_token.token);
                alreadyResolved = true;
            }

            // Should we get a new token?
            // If we don't have one, or ours is expiring soon, then yes!
            if(!access_token || access_token.renew_time < now) {
                // Yep, don't have one, or this one will expire soon.
                debug('Fetching new token because', access_token, now);

                const options = {
                    url: 'https://2387a4ea-11a4-4fe3-8c6c-00b8732b3933.predix-uaa.run.asv-pr.ice.predix.io/oauth/token',
                    headers: {
                        'cache-control': 'no-cache',
                        'content-type': 'application/x-www-form-urlencoded'
                    },
                    auth: {
                        username: 'acs-eval',
                        password: 'acs_client'
                    },
                    form: {
                        grant_type: 'client_credentials'
                    }
                };

                request.post(options, (err, resp, body) => {
                    const statusCode = (resp) ? resp.statusCode : 502;
                    if(err || statusCode !== 200) {
                        err = err || 'Error getting token: ' + statusCode;
                        debug('Error getting token from', config.token_url, err);
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

    return acs_utils;
}

