'use strict'
const testData = require('./data');
const chai = require('chai');
const expect = chai.expect;
const request = require('request');
const uaa = require('predix-uaa-client');
const sinon = require('sinon');
const match = sinon.match;
const acs_util = require('../index');

// ====================================================
// HELPERS

const acsEvalUri = 'https://predix-acs.test.predix.io/v1/policy-evaluation';

let acs_instance = null;
let token = null;
let uaaError = false;

beforeEach((done) => {

    acs_instance = acs_util(testData.testOptions);

    uaaError = false;

    // Sample token
    token = {
        access_token: 'ABC',
        expire_time: Date.now() + (123 * 1000),
        renew_time: Date.now() + (120 * 1000)
    };

    // Mock out the call to UAA
    sinon.stub(uaa, 'getToken', () => {
        return (uaaError) ? Promise.reject('nope - no token here') : Promise.resolve(token);
    });

    done();
});

afterEach((done) => {
    // Undo any sinon mocks
    if(request.get.restore) request.get.restore();
    if(request.post.restore) request.post.restore();
    if(uaa.getToken.restore) uaa.getToken.restore();
    done();
});

// ====================================================
// TESTS
describe('#Configuration', () => {

    it('should be configurable', () => {
        // Constructing should accept UAA client credentials, the ACS URI and the Predix Zone ID
        let instance = acs_util(testData.testOptions);
        expect(instance).to.exist;
    });

    it('should error with missing all configuration', () => {
        // Check that the error message contains the missing property
        expect(acs_util).to.throw(/uaa.uri/);
        expect(acs_util).to.throw(/uaa.clientId/);
        expect(acs_util).to.throw(/uaa.clientSecret/);
        expect(acs_util).to.throw(/acsUri/);
        expect(acs_util).to.throw(/zoneId/);
    });

    it('should error with missing single configuration - uaa.url', () => {
        // Constructing should error if required configuration is missing
        const options = {
            uaa: {
                clientId: 'test',
                clientSecret: 'secret'
            },
            acsUri: 'https://predix-acs.test.predix.io',
            zoneId: 'abcdefghi'
        };
        // Check that the error message contains the missing property
        expect(() => { acs_util(options); }).to.throw(/uaa.uri/);
    });

    it('should error with missing multiple configurations - uaa.url, acsUri', () => {
        // Constructing should error if required configuration is missing
        const options = {
            uaa: {
                clientId: 'test',
                clientSecret: 'secret'
            },
            zoneId: 'abcdefghi'
        };
        // Check that the error message contains the missing property
        expect(() => { acs_util(options); }).to.throw(/uaa.uri/);
        expect(() => { acs_util(options); }).to.throw(/acsUri/);
    });

    it('should error with missing while uaa object', () => {
        // Constructing should error if required configuration is missing
        const options = {
            acsUri: 'https://predix-acs.test.predix.io',
            zoneId: 'abcdefghi'
        };
        // Check that the error message contains the missing property
        expect(() => { acs_util(options); }).to.throw(/uaa.uri/);
        expect(() => { acs_util(options); }).to.throw(/uaa.clientId/);
        expect(() => { acs_util(options); }).to.throw(/uaa.clientSecret/);
    });
});


describe('#Parameter Checking', () => {
    it('should reject the promise if a null \'abacRequest\' value is provided', (done) => {
        // We expect a POST call with the HTTP Verb, Resource being accessed and the user subject
        let stub = sinon.stub(request, 'post');
        stub.yields(null, { statusCode: 200 }, testData.stubPermitResponse);

        acs_instance.isAuthorizedFor(null).then((result) => {
            // Expecting rejected promise
            done(new Error('Expected the promise to reject the invalid parameter, it instead completed successfully.'));
        }).catch((err) => {
            // parameter checking is done first, before the request is built and sent
            try {
                expect(stub.calledOnce).to.be.false; // should fail before the request is made
                done();
            } catch(fail) {
                done(fail);
            }
        });
    });

    it('should reject the promise if an undefined \'abacRequest\' value is provided', (done) => {
        // We expect a POST call with the HTTP Verb, Resource being accessed and the user subject
        let stub = sinon.stub(request, 'post');
        stub.yields(null, { statusCode: 200 }, testData.stubPermitResponse);

        const myObject = {};

        acs_instance.isAuthorizedFor(myObject.undefinedProperty).then((result) => {
            // Expecting rejected promise
            done(new Error('Expected the promise to reject the invalid parameter, it instead completed successfully.'));
        }).catch((err) => {
            // parameter checking is done first, before the request is built and sent
            try {
                expect(stub.calledOnce).to.be.false; // should fail before the request is made
                done();
            } catch(fail) {
                done(fail);
            }
        });
    });

    it('should reject the promise if the \'abacRequest\' is missing property \'subjectIdentifier\'', (done) => {
        // We expect a POST call with the HTTP Verb, Resource being accessed and the user subject
        let stub = sinon.stub(request, 'post');
        stub.yields(null, { statusCode: 200 }, testData.stubPermitResponse);

        const abacRequest = {action: 'GET', resourceIdentifier: 'foo'};

        acs_instance.isAuthorizedFor(abacRequest).then((result) => {
            // Expecting rejected promise
            done(new Error('Expected the promise to reject due to missing \'abacRequest.subjectIdentifier\' property, it instead completed successfully.'));
        }).catch((err) => {
            // parameter checking is done first, before the request is built and sent
            try {
                expect(stub.calledOnce).to.be.false; // should fail before the request is made
                done();
            } catch(fail) {
                done(fail);
            }
        });
    });

    it('should reject the promise if the \'abacRequest\' is missing property \'resourceIdentifier\'', (done) => {
        // We expect a POST call with the HTTP Verb, Resource being accessed and the user subject
        let stub = sinon.stub(request, 'post');
        stub.yields(null, { statusCode: 200 }, testData.stubPermitResponse);

        const abacRequest = {action: 'GET', subjectIdentifier: 'foo'};

        acs_instance.isAuthorizedFor(abacRequest).then((result) => {
            // Expecting rejected promise
            done(new Error('Expected the promise to reject due to missing \'abacRequest.resourceIdentifier\' property, it instead completed successfully.'));
        }).catch((err) => {
            // parameter checking is done first, before the request is built and sent
            try {
                expect(stub.calledOnce).to.be.false; // should fail before the request is made
                done();
            } catch(fail) {
                done(fail);
            }
        });
    });

    it('should reject the promise if the \'abacRequest\' is missing property \'action\'', (done) => {
        // We expect a POST call with the HTTP Verb, Resource being accessed and the user subject
        let stub = sinon.stub(request, 'post');
        stub.yields(null, { statusCode: 200 }, testData.stubPermitResponse);

        const abacRequest = {subjectIdentifier: 'foo', resourceIdentifier: 'bar'};

        acs_instance.isAuthorizedFor(abacRequest).then((result) => {
            // Expecting rejected promise
            done(new Error('Expected the promise to reject due to missing \'abacRequest.action\' property, it instead completed successfully.'));
        }).catch((err) => {
            // parameter checking is done first, before the request is built and sent
            try {
                expect(stub.calledOnce).to.be.false; // should fail before the request is made
                done();
            } catch(fail) {
                done(fail);
            }
        });
    });
});

describe('#Authorization', () => {
    it('should resolve the promise if authorized for the action', (done) => {
        // We expect a POST call with the HTTP Verb, Resource being accessed and the user subject
        let stub = sinon.stub(request, 'post');
        stub.yields(null, { statusCode: 200 }, testData.stubPermitResponse);

        const req = {
            method: 'GET',
            path: '/abc/def'
        };

        acs_instance.isAuthorized(req, 'test_user').then((result) => {
            // Result should be testData.stubPermitResponse
            // Check that the evaluate policy call was made correctly
            expect(stub.calledOnce).to.be.true;
            const acsReq = stub.firstCall.args[0];
            expect(acsReq.url).to.equal(testData.acsEvalUri);
            expect(acsReq.body.action).to.equal('GET');
            expect(acsReq.body.resourceIdentifier).to.equal('/abc/def');
            expect(acsReq.body.subjectIdentifier).to.equal('test_user');
            expect(acsReq.headers['Predix-Zone-Id']).to.equal(testData.testOptions.zoneId);
            done();
        }).catch((err) => {
            done(err);
        });
    });

    it('should reject the promise if not authorized for the action', (done) => {
        let stub = sinon.stub(request, 'post');
        stub.yields(null, { statusCode: 200 }, testData.stubDenyResponse);

        const req = {
            method: 'GET',
            path: '/xyz'
        };

        acs_instance.isAuthorized(req, 'test_user').then((result) => {
            // Expecting rejected promise
            done(new Error('Expected DENY, but got PERMIT'));
        }).catch((err) => {
            // err should be testData.stubDenyResponse
            // Check that the evaluate policy call was made correctly
            // Need to wrap these expects in try..catch because a failure will throw and not call done.
            try {
                expect(stub.calledOnce).to.be.true;
                const acsReq = stub.firstCall.args[0];
                expect(acsReq.url).to.equal(testData.acsEvalUri);
                expect(acsReq.body.action).to.equal('GET');
                expect(acsReq.body.resourceIdentifier).to.equal('/xyz');
                expect(acsReq.body.subjectIdentifier).to.equal('test_user');
                expect(acsReq.headers['Predix-Zone-Id']).to.equal(testData.testOptions.zoneId);
                expect(err.effect).to.equal('DENY');
                done();
            } catch(fail) {
                done(fail);
            }
        });
    });

    it('should reject the promise if unable to query ACS', (done) => {
        let stub = sinon.stub(request, 'post');
        stub.yields(null, { statusCode: 404 }, null);

        const req = {
            method: 'GET',
            path: '/xyz'
        };

        acs_instance.isAuthorized(req, 'test_user').then((result) => {
            // Expecting rejected promise
            done(new Error('Expected Reject, but got Resolve'));
        }).catch((err) => {
            // err should be testData.stubDenyResponse
            // Check that the evaluate policy call was made correctly
            // Need to wrap these expects in try..catch because a failure will throw and not call done.
            try {
                expect(stub.calledOnce).to.be.true;
                const acsReq = stub.firstCall.args[0];
                expect(acsReq.url).to.equal(testData.acsEvalUri);
                expect(acsReq.body.action).to.equal('GET');
                expect(acsReq.body.resourceIdentifier).to.equal('/xyz');
                expect(acsReq.body.subjectIdentifier).to.equal('test_user');
                expect(acsReq.headers['Predix-Zone-Id']).to.equal(testData.testOptions.zoneId);
                expect(err).to.match(/Error getting verdict/);
                done();
            } catch(fail) {
                done(fail);
            }
        });
    });

    it('should reject the promise if ACS does not respond', (done) => {
        let stub = sinon.stub(request, 'post');
        stub.yields(null, null, null);

        const req = {
            method: 'GET',
            path: '/xyz'
        };

        acs_instance.isAuthorized(req, 'test_user').then((result) => {
            // Expecting rejected promise
            done(new Error('Expected Reject, but got Resolve'));
        }).catch((err) => {
            // err should be testData.stubDenyResponse
            // Check that the evaluate policy call was made correctly
            // Need to wrap these expects in try..catch because a failure will throw and not call done.
            try {
                expect(stub.calledOnce).to.be.true;
                const acsReq = stub.firstCall.args[0];
                expect(acsReq.url).to.equal(testData.acsEvalUri);
                expect(acsReq.body.action).to.equal('GET');
                expect(acsReq.body.resourceIdentifier).to.equal('/xyz');
                expect(acsReq.body.subjectIdentifier).to.equal('test_user');
                expect(acsReq.headers['Predix-Zone-Id']).to.equal(testData.testOptions.zoneId);
                expect(err).to.match(/Error getting verdict/);
                done();
            } catch(fail) {
                done(fail);
            }
        });
    });

    it('should get a client token from UAA before calling ACS', (done) => {
        // We expect a POST call with the HTTP Verb, Resource being accessed and the user subject
        let stub = sinon.stub(request, 'post');
        stub.yields(null, { statusCode: 200 }, testData.stubPermitResponse);

        const req = {
            method: 'GET',
            path: '/abc/def'
        };

        // Reset the token to ensure this call is getting the one we set
        token.access_token = 'MY-TEST-TOKEN';

        acs_instance.isAuthorized(req, 'test_user').then((result) => {
            // Result should be testData.stubPermitResponse
            // Check that the evaluate policy call was made correctly
            expect(stub.calledOnce).to.be.true;
            const acsReq = stub.firstCall.args[0];
            expect(acsReq.url).to.equal(testData.acsEvalUri);
            expect(acsReq.body.action).to.equal('GET');
            expect(acsReq.body.resourceIdentifier).to.equal('/abc/def');
            expect(acsReq.body.subjectIdentifier).to.equal('test_user');
            expect(acsReq.headers['Predix-Zone-Id']).to.equal(testData.testOptions.zoneId);
            expect(acsReq.auth.bearer).to.equal(token.access_token);
            done();
        }).catch((err) => {
            done(err);
        });
    });

    it('should reject the promise if unable to get a client token', (done) => {
        let stub = sinon.stub(request, 'post');
        stub.yields(null, null, null);

        const req = {
            method: 'GET',
            path: '/xyz'
        };

        // Get our mocked UAA call to fail
        uaaError = true;

        acs_instance.isAuthorized(req, 'test_user').then((result) => {
            // Expecting rejected promise
            done(new Error('Expected Reject, but got Resolve'));
        }).catch((err) => {
            // err should be testData.stubDenyResponse
            // Check that the evaluate policy call was never made
            // Need to wrap these expects in try..catch because a failure will throw and not call done.
            try {
                expect(stub.notCalled).to.be.true;
                done();
            } catch(fail) {
                done(fail);
            }
        });
    });
});

describe('#Permissions', () => {
    it('should be able to query attributes assigned to a user', (done) => {
        // We expect a GET call with the HTTP Verb, username
        let stub = sinon.stub(request, 'get');
        stub.yields(null, { statusCode: 200 }, testData.stubSubjectPermitResponse);

        // Reset the token to ensure this call is getting the one we set
        token.access_token = 'MY-TEST-TOKEN';

        const subjectIdentifier = 'test_user'

        acs_instance.getSubjectAttributes(subjectIdentifier).then((result) => {
            // Result should be testData.stubSubjectPermitResponse
            // Check that the get subject call was made correctly
            expect(stub.calledOnce).to.be.true;
            const acsReq = stub.firstCall.args[0];
            expect(acsReq.url).to.equal(testData.acsSubjectUri + subjectIdentifier);
            expect(acsReq.headers['Predix-Zone-Id']).to.equal(testData.testOptions.zoneId);
            expect(acsReq.auth.bearer).to.equal(token.access_token);
            done();
        }).catch((err) => {
            done(err);
        });
    });

    it('should be able to query attributes required for a resourse', (done) => {
        // TODO: WRITE TEST
        done();
    });

    it('should reject the promise if unable to query ACS', (done) => {
        // TODO: WRITE TEST
        done();
    });
});
