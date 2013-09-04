var _ = require('underscore'),
	connect = null,
	forge = require('node-forge')({disableNativeCode: true}),
	webid = require('webid');


try {
	connect = require('connect');
} catch(e) {
	connect = require('express/node_modules/connect');
}


module.exports.getCertificateFromConnection = function(req) {
	if(_.isUndefined(req.connection.getPeerCertificate))
		return null;

	return req.connection.getPeerCertificate();
};


module.exports.getCertificateFromHeader = function(req) {
	if(_.isUndefined(req.headers['ssl_client_cert']))
		return null;

	var bigIntegerToString = function(number, radix) {
		var bn = new forge.jsbn.BigInteger("0");

		bn.data = number.data;
		bn.t = number.t;
		bn.s = number.s;

		return bn.toString(radix);
	};

	var pem = '-----BEGIN CERTIFICATE-----' + req.headers['ssl_client_cert'].replace(/\-{5,}[\w\s]*\-{5,}/g, '').replace(/[^0-9a-zA-Z\/\+\=]/g, '\n') + '-----END CERTIFICATE-----';

	forgeCertificate = forge.pki.certificateFromPem(pem);

	var subjectAlternativeName = forgeCertificate.extensions.filter(function(object) {return object.name == 'subjectAltName';});

	if(!_.isEmpty(subjectAlternativeName))
		subjectAlternativeName = 'URI:' + subjectAlternativeName[0].value.split(',')[1]; //TODO: check type
	else
		subjectAlternativeName = null;

	certificate = {
		subjectaltname: subjectAlternativeName,
		modulus: bigIntegerToString(forgeCertificate.publicKey.n, 16),
		exponent: bigIntegerToString(forgeCertificate.publicKey.e, 16) | 0,
	};

	return certificate;
};


module.exports.login = function(options) {	
	if(_.isUndefined(options))
		options = {};

	if(_.isUndefined(options.getCertificateCallback))
		options.getCertificateCallback = module.exports.getCertificateFromConnection;

	if(_.isUndefined(options.doRenegotiation))
		options.doRenegotiation = false;

	if(_.isUndefined(options.defaultUser))
		options.defaultUser = '_:anonymous';

	return function(req, res, next) {
		if(options.doRenegotiation)
			req.connection.ssl.setVerifyMode(true, false); //TODO: must be implemented in nodejs

		var certificate = options.getCertificateCallback(req);

		if(!_.isEmpty(certificate)) {
			var pause = connect.utils.pause(req);

			new webid.VerificationAgent(certificate).verify(function(result) {
				req.session.agent = result;
				next();
				pause.resume();
			}, function(result) {
				req.session.agent = options.defaultUser;
				next();
				pause.resume();
			});
		} else {
			next();
		}
	};
};
