'use strict'

let data = {};

data.stubPermitResponse = {
    "effect": "PERMIT",
    "subjectAttributes": [
        {
            "issuer": "https://acs.attributes.int",
            "name": "role",
            "value": "APP_USER",
            "scopes": null
        },
        {
            "issuer": "https://acs.attributes.int",
            "name": "work_hours",
            "value": "09:00-17:00 UTC",
            "scopes": null
        },
        {
            "issuer": "https://acs.attributes.int",
            "name": "role",
            "value": "WORKFLOW_APPROVER",
            "scopes": null
        }
    ],
    "resourceAttributes": [
        {
            "issuer": "https://acs.attributes.int",
            "name": "role",
            "value": "APP_USER",
            "scopes": null
        }
    ],
    "resolvedResourceUris": [
        "/abc/def"
    ],
    "timestamp": 1461451401499
};

data.stubDenyResponse = {
  "effect": "DENY",
  "subjectAttributes": [
      {
          "issuer": "https://acs.attributes.int",
          "name": "role",
          "value": "APP_USER",
          "scopes": null
      },
      {
          "issuer": "https://acs.attributes.int",
          "name": "work_hours",
          "value": "09:00-17:00 UTC",
          "scopes": null
      },
      {
          "issuer": "https://acs.attributes.int",
          "name": "role",
          "value": "WORKFLOW_APPROVER",
          "scopes": null
      }
  ],
  "resourceAttributes": [
    {
      "issuer": "https://acs.attributes.int",
      "name": "role",
      "value": "APP_ADMIN",
      "scopes": null
    }
  ],
  "resolvedResourceUris": [
    "/xyz"
  ],
  "timestamp": 1461526066994
};

data.testOptions = {
    uaa: {
        uri: 'https://predix-uaa.test.predix.io/oauth/token',
        clientId: 'test',
        clientSecret: 'secret'
    },
    acsUri: 'https://predix-acs.test.predix.io',
    zoneId: 'abcdefghi'
};

data.acsEvalUri = data.testOptions.acsUri + '/v1/policy-evaluation';

data.acsSubjectUri = data.testOptions.acsUri + '/v1/subject/';

data.stubSubjectPermitResponse = {
   "subjectIdentifier": "test_user",
   "attributes": [
     {
         "issuer": "https://acs.attributes.int",
         "name": "role",
         "value": "APP_USER",
         "scopes": null
     },
     {
         "issuer": "https://acs.attributes.int",
         "name": "work_hours",
         "value": "09:00-17:00 UTC",
         "scopes": null
     },
     {
         "issuer": "https://acs.attributes.int",
         "name": "role",
         "value": "WORKFLOW_APPROVER",
         "scopes": null
     }
   ]
 };

module.exports = data;
