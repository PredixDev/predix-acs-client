'use strict'
const testData = require('./data');
const chai = require('chai');
const expect = chai.expect;
const request = require('request');
const sinon = require('sinon');
const match = sinon.match;
const acs_util = require('../index');

// ====================================================
// HELPERS

const acsEvalUri = 'https://predix-acs.test.predix.io/v1/policy-evaluation';

let acs_instance = null;

beforeEach((done) => {
    acs_instance = acs_util(testData.testOptions);
    // Mock out the call to UAA
    acs_instance._getToken = () => {
        return new Promise((resolve, reject) => {
            resolve('fake-token-not-used-directly');
        });
    };

    done();
});

afterEach((done) => {
    // Undo any sinon mocks
    if(request.get.restore) request.get.restore();
    if(request.post.restore) request.post.restore();
    done();
});

// ====================================================
// TESTS
describe('#Configuration', () => {

    it('should be configurable', () => {
        // Constructing should accept UAA client credentials, the ACS URI and the Predix Zone ID
        let instance = acs_util(testData.testOptions);
        expect(instance).to.exist;
        // TODO: Add proper tests
    });

    it('should fetch a client token from UAA before calling ACS', (done) => {
        // We expect a POST call with the client credentials as Basic Auth.
        let stub = sinon.stub(request, 'post');
        stub.yields(null, { statusCode: 200 }, JSON.stringify({ access_token: 'test-token', expires_in: 123 }));

        // Configure a new instance, without mocking out the _getToken call, so we can test it.
        let instance = acs_util(testData.testOptions);

        instance._getToken().then((token) => {
            // Result should be our fake token
            // Check that the UAA call was made correctly
            expect(stub.calledOnce).to.be.true;
            expect(stub.calledWith(match({ uri: testData.testOptions.uaa.uri })));
            expect(stub.calledWith(match({ form: { grant_type: 'client_credentials' }})));
            expect(token).to.equal('test-token');
            done();
        }).catch((err) => {
            done(err);
        });
    });

    it('should not fetch a client token from UAA if not expiring soon', (done) => {
        // We expect a POST call with the client credentials as Basic Auth.
        let stub = sinon.stub(request, 'post');
        stub.yields(null, { statusCode: 200 }, JSON.stringify({ access_token: 'test-token-1', expires_in: 123 }));

        // Configure a new instance, without mocking out the _getToken call, so we can test it.
        let instance = acs_util(testData.testOptions);

        instance._getToken().then((token) => {
            // Result should be our fake token
            // Check that the UAA call was made correctly
            expect(stub.calledOnce).to.be.true;
            expect(stub.calledWith(match({ uri: testData.testOptions.uaa.uri })));
            expect(stub.calledWith(match({ form: { grant_type: 'client_credentials' }})));
            expect(token).to.equal('test-token-1');

            stub.yields(null, { statusCode: 200 }, JSON.stringify({ access_token: 'test-token-2', expires_in: 123 }));

            // Get it again, it should not call our stub again
            instance._getToken().then((token) => {
                // Stub should be called only once overall
                expect(stub.calledOnce).to.be.true;
                expect(token).to.equal('test-token-1');
                done();
            }).catch((err) => {
                done(err);
            });
        }).catch((err) => {
            done(err);
        });
    });

    it('should fetch a new client token from UAA if expiring soon, but give the current one', (done) => {
        // We expect a POST call with the client credentials as Basic Auth.
        let stub = sinon.stub(request, 'post');
        stub.yields(null, { statusCode: 200 }, JSON.stringify({ access_token: 'test-token-1', expires_in: 10 }));

        // Configure a new instance, without mocking out the _getToken call, so we can test it.
        let instance = acs_util(testData.testOptions);

        instance._getToken().then((token) => {
            // Result should be our fake token
            // Check that the UAA call was made correctly
            expect(stub.calledOnce).to.be.true;
            expect(stub.calledWith(match({ uri: testData.testOptions.uaa.uri })));
            expect(stub.calledWith(match({ form: { grant_type: 'client_credentials' }})));
            expect(token).to.equal('test-token-1');

            stub.yields(null, { statusCode: 200 }, JSON.stringify({ access_token: 'test-token-2', expires_in: 1000 }));

            // Get it again, it should give the first token, but still call the stub again
            instance._getToken().then((token) => {
                // Stub should be called twice overall
                expect(stub.calledTwice).to.be.true;
                expect(token).to.equal('test-token-1');

                // Get it one more time, to prove that we got another new token
                instance._getToken().then((token) => {
                    // Stub should be called twice overall
                    expect(stub.calledTwice).to.be.true;
                    // But now have the new token
                    expect(token).to.equal('test-token-2');
                    done();
                }).catch((err) => {
                    done(err);
                });

            }).catch((err) => {
                done(err);
            });
        }).catch((err) => {
            done(err);
        });
    });

    it('should fetch a new client token from UAA if already expired', (done) => {
        // We expect a POST call with the client credentials as Basic Auth.
        let stub = sinon.stub(request, 'post');
        stub.yields(null, { statusCode: 200 }, JSON.stringify({ access_token: 'test-token-1', expires_in: 0 }));

        // Configure a new instance, without mocking out the _getToken call, so we can test it.
        let instance = acs_util(testData.testOptions);

        instance._getToken().then((token) => {
            // Result should be our fake token
            // Check that the UAA call was made correctly
            expect(stub.calledOnce).to.be.true;
            expect(stub.calledWith(match({ uri: testData.testOptions.uaa.uri })));
            expect(stub.calledWith(match({ form: { grant_type: 'client_credentials' }})));
            expect(token).to.equal('test-token-1');

            stub.yields(null, { statusCode: 200 }, JSON.stringify({ access_token: 'test-token-2', expires_in: 1000 }));

            // Get it again, it should give us the new token
            instance._getToken().then((token) => {
                // Stub should be called twice overall
                expect(stub.calledTwice).to.be.true;
                expect(token).to.equal('test-token-2');
                done();
            }).catch((err) => {
                done(err);
            });
        }).catch((err) => {
            done(err);
        });
    });

    it('should fail if getting an error while calling UAA', (done) => {
        // We expect a POST call with the client credentials as Basic Auth.
        let stub = sinon.stub(request, 'post');
        stub.yields('nope', { statusCode: 403 }, null);

        // Configure a new instance, without mocking out the _getToken call, so we can test it.
        let instance = acs_util(testData.testOptions);

        instance._getToken().then((token) => {
            done(new Error('Expected error, but got token'));
        }).catch((err) => {
            done();
        });
    });

    it('should fail if no response while calling UAA', (done) => {
        // We expect a POST call with the client credentials as Basic Auth.
        let stub = sinon.stub(request, 'post');
        stub.yields(null, null, null);

        // Configure a new instance, without mocking out the _getToken call, so we can test it.
        let instance = acs_util(testData.testOptions);

        instance._getToken().then((token) => {
            done(new Error('Expected error, but got token'));
        }).catch((err) => {
            done();
        });
    });

    it('should still return a token, if valid, even if fetching a new one has an error', (done) => {
        // Make the token appear to expire soon, but not yet
        let stub = sinon.stub(request, 'post');
        stub.yields(null, { statusCode: 200 }, JSON.stringify({ access_token: 'test-token-1', expires_in: 10 }));

        // Configure a new instance, without mocking out the _getToken call, so we can test it.
        let instance = acs_util(testData.testOptions);

        instance._getToken().then((token) => {
            // Result should be our fake token
            // Check that the UAA call was made correctly
            expect(stub.calledOnce).to.be.true;
            expect(stub.calledWith(match({ uri: testData.testOptions.uaa.uri })));
            expect(stub.calledWith(match({ form: { grant_type: 'client_credentials' }})));
            expect(token).to.equal('test-token-1');

            // Make the next call fail
            stub.yields('Oh no', { statusCode: 403 }, null);

            // Get it again, it should give the first token, but still call the stub again
            instance._getToken().then((token) => {
                // Stub should be called twice overall
                expect(stub.calledTwice).to.be.true;
                expect(token).to.equal('test-token-1');
                done();
            }).catch((err) => {
                done(err);
            });
        }).catch((err) => {
            done(err);
        });
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

describe('#Authroization', () => {
    it('should resolve the promise if authorized for the action', (done) => {
        // We expect a POST call with the HTTP Verb, Resource being accessed and the user subject
        let stub = sinon.stub(request, 'post').returns(testData.stubPermitResponse);

        const req = {
            method: 'GET',
            path: '/abc/def'
        };

        acs_util.isAuthorized(req, 'test_user').then((result) => {
            // Result should be testData.stubPermitResponse
            // Check that the evaluate policy call was made correctly
            expect(stub.calledOnce).to.be.true;
            expect(stub.calledWith(match({ uri: acsEvalUri })));
        }).catch((err) => {
            done(err);
        });
    });

    it('should reject the promise if not authorized for the action', (done) => {
        // TODO: WRITE TEST
        done();
    });

    it('should reject the promise if unable to query ACS', (done) => {
        // TODO: WRITE TEST
        done();
    });
});

describe('#Permissions', () => {
    it('should be able to query attributes assigned to a user', (done) => {
        // TODO: WRITE TEST
        done();
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
