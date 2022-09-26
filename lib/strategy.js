/**
 * Module dependencies.
 */

var passport = require("passport-strategy"),
  url = require("url"),
  https = require("https"),
  util = require("util");

/**
 * `Strategy` constructor.
 *
 * @constructor
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function ZaloStrategy(options, verify) {
  if (typeof options == "function") {
    verify = options;
    options = undefined;
  }
  options = options || {};

  if (!verify) {
    throw new TypeError("ZaloStrategy requires a verify callback");
  }
  if (!options.appId) {
    throw new TypeError("ZaloStrategy requires an app_id option");
  }
  if (!options.appSecret) {
    throw new TypeError("ZaloStrategy requires an app_secret option");
  }
  if (!options.callbackURL) {
    throw new TypeError("ZaloStrategy require an Callback URL option");
  }

  passport.Strategy.call(this);
  this.name = "zalo";
  this._verify = verify;
  this._options = options;
  this._authURL = "https://oauth.zaloapp.com/v4/oa/permission";
  this._accessTokenURL = "https://oauth.zaloapp.com/v4/oa/access_token";
  this._getOaURL = "https://openapi.zalo.me/v2.0/oa/getoa";
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(ZaloStrategy, passport.Strategy);

/**
 * Authenticate request.
 *
 * This function must be overridden by subclasses.  In abstract form, it always
 * throws an exception.
 *
 * @param {Object} req The request to authenticate.
 * @param {Object} [options] Strategy-specific options.
 * @api public
 */

ZaloStrategy.prototype.authenticate = function (req, options) {
  options = options || {};
  var self = this;
  if (req.query && req.query.code) {
    self.getOAuthAccessToken(req.query.code, function (err, oauthData) {
      if (err !== null) {
        return self.error(err);
      } else {

        self.getOA(oauthData, function (
          err,
          oaData
        ) {
          if (err !== null) {
            return self.error(err);
          } else {
            self._verify(
              req, // req
              oauthData.access_token, // access token
              oauthData.refresh_token, // refresh token
              { expires_in: oauthData.expires_in }, // params
              oaData, // oa profile
              function (err, oa, info) {
                if (err) { return self.error(err); }
                if (!oa) { return self.fail(info); }

                info = info || {};
                // if (userProfileData) { info.state = userProfileData; }
                self.success(oa, info);
              }
            );
          }
        });
      }
    });
  } else {
    // Building URL for get Access token
    var authUrlObject = url.parse(self._authURL);
    var params = {
      app_id: self._options.appId,
      redirect_uri: self._options.callbackURL,
      state: self._options.state,
    };
    authUrlObject.query = params;
    var location = url.format(authUrlObject);
    this.redirect(location);
  }
};

/**
 * Get access token when have code return from request permission
 * URL to load is: https://oauth.zaloapp.com/v3/access_token?app_id={1}&app_secret={2}&code={3}
 *
 * @param {String} code
 * @param {Function} done
 * @api private
 */
ZaloStrategy.prototype.getOAuthAccessToken = function (code, done) {
  var accessTokenURLObject = url.parse(this._accessTokenURL);
  var accessTokenParams = {
    app_id: this._options.appId,
    code: code,
    grant_type: 'authorization_code',
  };

  accessTokenParams = `app_id=${accessTokenParams.app_id}&code=${accessTokenParams.code}&grant_type=${accessTokenParams.grant_type}`

  var accessTokenURL = url.format(accessTokenURLObject);
  accessTokenURLObject = url.parse(accessTokenURL);

  const requestOptions = {
    port: 443,
    hostname: accessTokenURLObject.hostname,
    path: accessTokenURLObject.path,
    method: "POST",
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Content-Length': accessTokenParams.length,
      'secret_key': this._options.appSecret,
    }
  };

  const accessTokenRequest = https.request(requestOptions, (res) => {
    res.on("data", (d) => {
      const response = JSON.parse(d);
      if (response.error) {
        const err = new Error(response.error_name)
        err.code = response.error
        return done(err)
      }
      done(null, response);
    });
  });

  accessTokenRequest.on("error", (error) => {
    done("error", error);
  });

  accessTokenRequest.write(accessTokenParams);
  accessTokenRequest.end();
};

/**
 * Load basic user profile when we have access token
 * URL to load is: https://graph.zalo.me/v2.0/me?access_token=<User_Access_Token>&fields=id,birthday,name,gender,picture
 *
 * @param {String} accessTokenObject
 * @param {Function} done
 * @api private
 */

ZaloStrategy.prototype.getOA = function (accessTokenObject, done) {

  const getOaUrl = new URL(this._getOaURL)

  const requestOptions = {
    hostname: getOaUrl.hostname,
    path: getOaUrl.pathname,
    method: "GET",
    headers: {
      access_token: accessTokenObject.access_token
    }
  };

  const accessTokenRequest = https.request(requestOptions, (res) => {
    res.on("data", (d) => {
      const oaData = JSON.parse(d);
      if (oaData.error) {
        const err = new Error(oaData.message)
        err.code = oaData.error
        done(err)
      } else {
        done(null, oaData);
      }
    });
  });

  accessTokenRequest.on("error", (error) => {
    done(error);
  });

  accessTokenRequest.end();
};

/**
 * Expose `Strategy`.
 */
module.exports = ZaloStrategy;