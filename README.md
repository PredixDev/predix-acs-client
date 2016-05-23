# predix-acs-client
Node module to check authorization for a user to perform an action against Predix ACS policies.
Primarily used when protecting REST endpoints with UAA JWT tokens.

NOTE that the client credentials that you use to query ACS must have the appropriate permissions to do so.
As this is a UAA client, these should be added as authorities, not scopes.
The minimun is ``acs.policies.read`` and ``predix-acs.zones.your-acs-zone-id.user``

## Usage
Install via npm

```
npm install --save git://github.build.ge.com/hubs/predix-acs-client.git
```

Basic usage with a known user and ACS endpoint

```javascript
const config = {
    uaa: {
        uri: 'https://your-uaa-service.predix.io/oauth/token',
        clientId: 'your-uaa-client',
        clientSecret: 'your-uaa-secret'
    },
    acsUri: 'https://predix-acs.example.predix.io',
    zoneId: 'your-acs-zone-id'
};
const acs = require('predix-acs-client')(config);
acs.isAuthorized({ method: 'GET', path: 'example' }, 'my-user').then((result) => {
     // 'my-user' is authorized to perform the 'GET' action on the 'example' resource.
     console.log('Permission Granted');
}).catch((err) => {
    // Not authorized, or unable to check permissions due to an error
    console.log('No access for you', err);
});
```

As an expressjs middleware

```javascript
'use strict';
const express = require('express');
const app = express();

// Configure the ACS client
const options = {
    uaa: {
        uri: 'https://your-uaa-service.predix.io/oauth/token',
        clientId: 'your-uaa-client',
        clientSecret: 'your-uaa-secret'
    },
    acsUri: 'https://predix-acs.example.predix.io',
    zoneId: 'your-acs-zone-id'
};
const acs = require('predix-acs-client')(options);

app.get('/hello', (req, res, next) => {
    res.send('Howdy, you can read this without authorization!');
});

// To ensure Authorization header has a bearer token
// use something like predix-fast-token https://github.build.ge.com/hubs/predix-fast-token

// This assumes that the user token has been validated already
app.all('*', (req, res, next) => {
    // This would come from the token
    const username = 'demo';

	// This defaults to using:
	// req.method as the ACS action
	// req.path as the ACS resourceIdentifier
	// username as the ACS subjectIdentifier
	// If you want to use a resource name other than the path,
	// just pass in a new object - see example above
    acs.isAuthorized(req, username).then((result) => {
        console.log('Access is permitted');
        next();
    }).catch((err) => {
        console.log('Nope', err, err.stack);
        res.status(403).send('Unauthorized');
    });
});

app.get('/secure', (req, res, next) => {
    res.send('Hello, my authorized chum!');
});

// Need to let CF set the port if we're deploying there.
const port = process.env.PORT || 9001;
app.listen(port);
console.log('Started on port ' + port);
```

Working together with [predix-fast-token](https://github.build.ge.com/hubs/predix-fast-token) as an expressjs middleware

```javascript
'use strict';
const express = require('express');
const bearerToken = require('express-bearer-token');
const predixFastToken = require('predix-fast-token');
const app = express();

// Configure the ACS client
const options = {
    uaa: {
        uri: 'https://your-uaa-service.predix.io/oauth/token',
        clientId: 'your-uaa-client',
        clientSecret: 'your-uaa-secret'
    },
    acsUri: 'https://predix-acs.example.predix.io',
    zoneId: 'your-acs-zone-id'
};
const acs = require('predix-acs-client')(options);

const trusted_issuers = ['https://abc.predix-uaa.example.predix.io/oauth/token', 'https://xyz.predix-uaa.example.predix.io/oauth/token/oauth/token'];

app.get('/hello', (req, res, next) => {
    res.send('Howdy my unsecured friend!');
});

// Ensure Authorization header has a bearer token
app.all('*', bearerToken(), function(req, res, next) {
    console.log('Req Headers', req.headers);
    if(req.token) {
        predixFastToken.verify(req.token, trusted_issuers).then((decoded) => {
            acs.isAuthorized(req, decoded.user_name).then((result) => {
                console.log('Access is permitted');
                req.decoded = decoded;
                console.log('Looks good');
                next();
            }).catch((err) => {
                console.log('Nope', err);
                res.status(403).send('Unauthorized');
            });
        }).catch((err) => {
            console.log('Nope', err);
            res.status(403).send('Unauthorized');
        });
    } else {
        console.log('Nope, no token');
        res.status(401).send('Authentication Required');
    }
});

app.get('/secure', (req, res, next) => {
    res.send('Hello ' + req.decoded.user_name + ', my authenticated chum!');
});

// Need to let CF set the port if we're deploying there.
const port = process.env.PORT || 9001;
app.listen(port);
console.log('Started on port ' + port);
```
