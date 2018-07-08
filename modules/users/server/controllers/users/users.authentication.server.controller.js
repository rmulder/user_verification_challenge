'use strict';

/**
 * Module dependencies
 */
var path = require('path'),
  errorHandler = require(path.resolve('./modules/core/server/controllers/errors.server.controller')),
  mongoose = require('mongoose'),
  passport = require('passport'),
  User = mongoose.model('User'),
  _ = require('lodash');

const request = require('request-promise-native');
const Trulioo_API_Key = 'Ciitizen_Demo_API';
const Trulioo_API_Password = 'Ciitizen_Demo634!';

// URLs for which user can't be redirected on signin
var noReturnUrls = [
  '/authentication/signin',
  '/authentication/signup'
];

/**
 * Signup
 */
exports.signup = function (req, res) {
  // For security measurement we remove the roles from the req.body object
  console.log('inside users.authentication.server.controller - signup - req.body: ', req.body);
  delete req.body.roles;

  // Init user and add missing fields
  var user = new User(req.body);
  user.provider = 'local';
  user.displayName = user.firstName + ' ' + user.lastName;
  user.additionalProvidersData = {
    Gender: req.body.Gender || '',
    MiddleName: req.body.MiddleName || '',
    MonthOfBirth: req.body.MonthOfBirth || '',
    DayOfBirth: req.body.DayOfBirth || '',
    YearOfBirth: req.body.YearOfBirth || '',
    PostalCode: req.body.PostalCode || '',
    City: req.body.City || '',
    StateProvinceCode: req.body.StateProvinceCode || '',
    BuildingNumber: req.body.BuildingNumber || '',
    StreetName: req.body.StreetName || '',
    DriverLicenceNumber: req.body.DriverLicenceNumber || '',
    DriverLicenceState: req.body.DriverLicenceState || ''
  };
  /*
  _.forEach(req.body.additionalProvidersData, (val, key) => {
    options.json.DataFields.PersonInfo[key] = '' + val;
    console.log('key: ' + key, 'val: ', val);
  });
  */

  console.log('inside users.authentication.server.controller - signup - user: ', user);

  // Then save the user
  user.save(function (err) {
    if (err) {
      return res.status(422).send({
        message: errorHandler.getErrorMessage(err)
      });
    } else {
      // Remove sensitive data before login
      user.password = undefined;
      user.salt = undefined;

      req.login(user, function (err) {
        if (err) {
          res.status(400).send(err);
        } else {
          console.log('user.save - returning: ', user);
          res.json(user);
        }
      });
    }
  });
};

function base64() {
  var keyStr = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';

  return {
    encode: function (input) {
      var output = '';
      var chr1 = '';
      var chr2 = '';
      var chr3 = '';
      var enc1 = '';
      var enc2 = '';
      var enc3 = '';
      var enc4 = '';
      var i = 0;

      do {
        chr1 = input.charCodeAt(i++);
        chr2 = input.charCodeAt(i++);
        chr3 = input.charCodeAt(i++);

        enc1 = chr1 >> 2;
        enc2 = ((chr1 & 3) << 4) | (chr2 >> 4);
        enc3 = ((chr2 & 15) << 2) | (chr3 >> 6);
        enc4 = chr3 & 63;

        if (isNaN(chr2)) {
          enc3 = enc4 = 64;
        } else if (isNaN(chr3)) {
          enc4 = 64;
        }

        output = output +
          keyStr.charAt(enc1) +
          keyStr.charAt(enc2) +
          keyStr.charAt(enc3) +
          keyStr.charAt(enc4);
        chr1 = chr2 = chr3 = '';
        enc1 = enc2 = enc3 = enc4 = '';
      } while (i < input.length);

      return output;
    },

    decode: function (input) {
      var output = '';
      var chr1 = '';
      var chr2 = '';
      var chr3 = '';
      var enc1 = '';
      var enc2 = '';
      var enc3 = '';
      var enc4 = '';
      var i = 0;

      // remove all characters that are not A-Z, a-z, 0-9, +, /, or =
      var base64test = /[^A-Za-z0-9\+\/\=]/g;
      if (base64test.exec(input)) {
        console.log('There were invalid base64 characters in the input text.\n' +
          'Valid base64 characters are A-Z, a-z, 0-9, \'+\', \'/\',and \'=\'\n' +
          'Expect errors in decoding.');
      }

      input = input.replace(/[^A-Za-z0-9\+\/\=]/g, '');

      do {
        enc1 = keyStr.indexOf(input.charAt(i++));
        enc2 = keyStr.indexOf(input.charAt(i++));
        enc3 = keyStr.indexOf(input.charAt(i++));
        enc4 = keyStr.indexOf(input.charAt(i++));

        chr1 = (enc1 << 2) | (enc2 >> 4);
        chr2 = ((enc2 & 15) << 4) | (enc3 >> 2);
        chr3 = ((enc3 & 3) << 6) | enc4;

        output = output + String.fromCharCode(chr1);

        if (enc3 !== 64) {
          output = output + String.fromCharCode(chr2);
        }

        if (enc4 !== 64) {
          output = output + String.fromCharCode(chr3);
        }

        chr1 = chr2 = chr3 = '';
        enc1 = enc2 = enc3 = enc4 = '';

      } while (i < input.length);

      return output;
    }
  };
}

/**
 * Verify User
 */
exports.verify = function (req, res, next) {
  // For security measurement we remove the roles from the req.body object
  console.log('inside users.authentication.server.controller - verify - req.body: ', req.body);
  delete req.body.roles;

  const b64 = base64();
  const authdata = b64.encode(Trulioo_API_Key + ':' + Trulioo_API_Password);
  // GET https://api.globaldatacompany.com/connection/v1/testauthentication
  const url = 'https://api.globaldatacompany.com/verifications/v1/verify';

  let options = {
    method: 'POST',
    uri: url,
    headers: {
      'Authorization': 'Basic ' + authdata,
      'content-type': 'application/json'
    },
    data: {},
    json: {
      AcceptTruliooTermsAndConditions: true,
      CountryCode: 'US',
      DataFields: {
        PersonInfo: {
          FirstGivenName: req.body.firstName,
          FirstSurName: req.body.lastName
        },
        Location: {},
        DriverLicence: {}
      }
    }
  };

  const personInfoFields = ['MiddleName', 'DayOfBirth', 'MonthOfBirth', 'YearOfBirth', 'Gender'];
  const locationFields = ['BuildingNumber', 'StreetName', 'City', 'StateProvinceCode', 'PostalCode'];
  const driverLicenseFields = ['DriverLicenceNumber', 'DriverLicenceState'];

  _.forEach(req.body.additionalProvidersData, (val, key) => {
    console.log('key: ' + key, 'val: ', val);
    if (personInfoFields.indexOf(key) > -1) {
      options.json.DataFields.PersonInfo[key] = '' + val;
    } else if (locationFields.indexOf(key) > -1) {
      options.json.DataFields.Location[key] = '' + val;
    } else if (driverLicenseFields.indexOf(key) > -1) {
      if (key === 'DriverLicenceState') { key = 'State'; }
      if (key === 'DriverLicenceNumber') { key = 'Number'; }
      options.json.DataFields.DriverLicence[key] = '' + val;
    }
  });

  let rtnData = {};
  request(options)
    .then(data => {
      console.log('data: ', data, 'req.body: ', req.body);

      // Init user and add missing fields
      var user = new User(req.body);
      user.additionalProvidersData = user.additionalProvidersData || {};
      user.additionalProvidersData.verificationResults = JSON.stringify(data);
      res.json(user);
      /*
      // Then tell mongoose that we've updated the additionalProvidersData field
      user.markModified('additionalProvidersData');
      console.log('before user.save: ', user);

      user.save(function (err) {
        if (err) {
          return res.status(422).send({
            message: errorHandler.getErrorMessage(err)
          });
        } else {
          // Remove sensitive data before login
          user.password = undefined;
          user.salt = undefined;
          res.json(user);
        }
      });
      */
    }).catch(err => {
      console.log(err);
    });
};

/**
 * Signin after passport authentication
 */
exports.signin = function (req, res, next) {
  passport.authenticate('local', function (err, user, info) {
    if (err || !user) {
      res.status(422).send(info);
    } else {
      // Remove sensitive data before login
      user.password = undefined;
      user.salt = undefined;

      req.login(user, function (err) {
        if (err) {
          res.status(400).send(err);
        } else {
          res.json(user);
        }
      });
    }
  })(req, res, next);
};

/**
 * Signout
 */
exports.signout = function (req, res) {
  req.logout();
  res.redirect('/');
};

/**
 * OAuth provider call
 */
exports.oauthCall = function (req, res, next) {
  var strategy = req.params.strategy;
  // Authenticate
  passport.authenticate(strategy)(req, res, next);
};

/**
 * OAuth callback
 */
exports.oauthCallback = function (req, res, next) {
  var strategy = req.params.strategy;

  // info.redirect_to contains inteded redirect path
  passport.authenticate(strategy, function (err, user, info) {
    if (err) {
      return res.redirect('/authentication/signin?err=' + encodeURIComponent(errorHandler.getErrorMessage(err)));
    }

    if (!user) {
      return res.redirect('/authentication/signin');
    }

    req.login(user, function (err) {
      if (err) {
        return res.redirect('/authentication/signin');
      }

      return res.redirect(info.redirect_to || '/');
    });
  })(req, res, next);
};

/**
 * Helper function to save or update a OAuth user profile
 */
exports.saveOAuthUserProfile = function (req, providerUserProfile, done) {
  // Setup info and user objects
  var info = {};
  var user;

  // Set redirection path on session.
  // Do not redirect to a signin or signup page
  if (noReturnUrls.indexOf(req.session.redirect_to) === -1) {
    info.redirect_to = req.session.redirect_to;
  }

  // Define a search query fields
  var searchMainProviderIdentifierField = 'providerData.' + providerUserProfile.providerIdentifierField;
  var searchAdditionalProviderIdentifierField = 'additionalProvidersData.' + providerUserProfile.provider + '.' + providerUserProfile.providerIdentifierField;

  // Define main provider search query
  var mainProviderSearchQuery = {};
  mainProviderSearchQuery.provider = providerUserProfile.provider;
  mainProviderSearchQuery[searchMainProviderIdentifierField] = providerUserProfile.providerData[providerUserProfile.providerIdentifierField];

  // Define additional provider search query
  var additionalProviderSearchQuery = {};
  additionalProviderSearchQuery[searchAdditionalProviderIdentifierField] = providerUserProfile.providerData[providerUserProfile.providerIdentifierField];

  // Define a search query to find existing user with current provider profile
  var searchQuery = {
    $or: [mainProviderSearchQuery, additionalProviderSearchQuery]
  };

  // Find existing user with this provider account
  User.findOne(searchQuery, function (err, existingUser) {
    if (err) {
      return done(err);
    }

    if (!req.user) {
      if (!existingUser) {
        var possibleUsername = providerUserProfile.username || ((providerUserProfile.email) ? providerUserProfile.email.split('@')[0] : '');

        User.findUniqueUsername(possibleUsername, null, function (availableUsername) {
          user = new User({
            firstName: providerUserProfile.firstName,
            lastName: providerUserProfile.lastName,
            username: availableUsername,
            displayName: providerUserProfile.displayName,
            profileImageURL: providerUserProfile.profileImageURL,
            provider: providerUserProfile.provider,
            providerData: providerUserProfile.providerData
          });

          // Email intentionally added later to allow defaults (sparse settings) to be applid.
          // Handles case where no email is supplied.
          // See comment: https://github.com/meanjs/mean/pull/1495#issuecomment-246090193
          user.email = providerUserProfile.email;

          // And save the user
          user.save(function (err) {
            return done(err, user, info);
          });
        });
      } else {
        return done(err, existingUser, info);
      }
    } else {
      // User is already logged in, join the provider data to the existing user
      user = req.user;

      // Check if an existing user was found for this provider account
      if (existingUser) {
        if (user.id !== existingUser.id) {
          return done(new Error('Account is already connected to another user'), user, info);
        }

        return done(new Error('User is already connected using this provider'), user, info);
      }

      // Add the provider data to the additional provider data field
      if (!user.additionalProvidersData) {
        user.additionalProvidersData = {};
      }

      user.additionalProvidersData[providerUserProfile.provider] = providerUserProfile.providerData;

      // Then tell mongoose that we've updated the additionalProvidersData field
      user.markModified('additionalProvidersData');

      // And save the user
      user.save(function (err) {
        return done(err, user, info);
      });
    }
  });
};

/**
 * Remove OAuth provider
 */
exports.removeOAuthProvider = function (req, res, next) {
  var user = req.user;
  var provider = req.query.provider;

  if (!user) {
    return res.status(401).json({
      message: 'User is not authenticated'
    });
  } else if (!provider) {
    return res.status(400).send();
  }

  // Delete the additional provider
  if (user.additionalProvidersData[provider]) {
    delete user.additionalProvidersData[provider];

    // Then tell mongoose that we've updated the additionalProvidersData field
    user.markModified('additionalProvidersData');
  }

  user.save(function (err) {
    if (err) {
      return res.status(422).send({
        message: errorHandler.getErrorMessage(err)
      });
    } else {
      req.login(user, function (err) {
        if (err) {
          return res.status(400).send(err);
        } else {
          return res.json(user);
        }
      });
    }
  });
};
