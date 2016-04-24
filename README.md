# predix-acs-client
Node module to check authorization for a user to perform an action against Predix ACS policies.
Primarily used when protecting REST endpoints with UAA JWT tokens.

## Usage
Install via npm

```
npm install --save git://github.build.ge.com/hubs/predix-acs-client.git
```

Basic usage with a JWT token and ACS endpoint

```javascript
// TODO: Provide example
```

As an expressjs middleware

```javascript
'use strict';
const express = require('express');
const bearerToken = require('express-bearer-token');
const acs = require('predix-acs-client');
const app = express();

const acs_server = ['https://acs.predix.io'];

app.get('/hello', (req, res, next) => {
    res.send('Howdy my unsecured friend!');
});

// Ensure Authorization header has a bearer token
app.all('*', bearerToken(), function(req, res, next) {
    console.log('Req Headers', req.headers);
    if(req.token) {
        acs.authorize(req.token, acs_server, 'action').then(() => {
            console.log('You may pass');
            next();
        }).catch((err) => {
            console.log('Nope, not allowed', err);
            res.status(403).send('Unauthorized');
        });
    } else {
        console.log('Nope', err);
        res.status(401).send('Authentication Required');
    }
});

app.get('/secure', (req, res, next) => {
    res.send('Hello, you may see this!');
});

// Need to let CF set the port if we're deploying there.
const port = process.env.PORT || 9001;
app.listen(port);
console.log('Started on port ' + port);

```