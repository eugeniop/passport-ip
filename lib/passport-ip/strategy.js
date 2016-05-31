/**
 * Module dependencies.
 */
var passport = require('passport')
  , util = require('util')
  , BadRequestError = require('./errors/badrequesterror')
  , NullStateStore = require('./state/null')
  , range_check = require('range_check');


/**
 * `Strategy` constructor.
 *
 * The IP based authentication strategy authenticates requests based on the
 * IP address of the requestor against a range configured at constructor.
 *
 * Applications must supply a `verify` callback which accepts `username` and
 * `password` credentials, and then calls the `done` callback supplying a
 * `user`, which should be set to `false` if the credentials are not valid.
 * If an exception occured, `err` should be set.
 *
 * Optionally, `options` can be used to change the fields in which the
 * credentials are found.
 *
 * Options:
 *   - `range` the range of IP address to check: '10.10.10.1/9' or ['10.10.10.1/9', '10.10.10.10/20'].
 *   - `username` the optional username to add to the profile associated to all ranges specified.
 *   - `passReqToCallback`  when `true`, `req` is the first argument to the verify callback (default: `false`).
 *
 * Examples:
 *
 *     passport.use(new IPStrategy(
 *       function(client, done) {
 *         console.log(client.id); //equal to the IP address
 *         done(null, {user_id: client.id});
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
  if (typeof options == 'function') {
    verify = options;
    options = {};
  }

  if (!verify) { throw new Error('IP authentication strategy requires a verify function'); }
  if (!options.range) { throw new Error('IP authentication strategy requires an IP Range parameter'); }

  this._range = options.range;

  passport.Strategy.call(this);

  this.name = 'ip';
  this._verify = verify;
  this._passReqToCallback = options.passReqToCallback;
  this._username = options.username;

  if (options.store) {
    this._stateStore = options.store;
  } else {
    this._stateStore = new NullStateStore();
  }
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);

/**
 * Authenticate request based on the client IP address
 *
 * @param {Object} req
 * @param {Object} options
 * @api protected
 */
Strategy.prototype.authenticate = function(req, options) {
  var self = this;
  var meta = {};

  options = options || {};

  if (!req.query || !req.query.code) {
    //First time we force a redirect to kick-off the 2nd stage of Auth0 authN
    var location = '/login/callback?code=dummy'; // TODO: add an option to override this
    var state = options.state;
    
    if (state) {
      location += '&state=' + state;
      self.redirect(location);
    } else {
      function stored(err, state) {
        if (err) { return self.error(err); }
        if (state) {
          location += '&state=' + state;
        }

        self.redirect(location);
      }
      
      try {
        var arity = self._stateStore.store.length;
        if (arity == 3) {
          self._stateStore.store(req, meta, stored);
        } else { // arity == 2
          self._stateStore.store(req, stored);
        }
      } catch (ex) {
        return self.error(ex);
      }
    }
  } else {
    //we are back from the redirect. Check the IP address
    function loaded(err, ok, state) {
      if (err) { return self.error(err); }
      if (!ok) {
        return self.fail(state, 403);
      }

      if (!req.ip) {
        return self.fail(new BadRequestError("Unknown ip address."));
      }

      if (!range_check.in_range(req.ip, self._range)) {
        return self.fail("Client IP: " + req.ip + ", is outside the range specified for this strategy.");
      }

      var client = {
        id: req.ip,
        provider: self.name,
        displayName: req.ip
      };

      if (self._username) {
        client.username = self._username;
      }

      function verified(err, user, info) {
        if (err) { return self.error(err); }
        if (!user) { return self.fail(new Error('No user in verified callback.')); }

        info = info || {};
        if (state) { info.state = state; }
        self.success(user, info);
      }

      if (self._passReqToCallback) {
        self._verify(req, client, verified);
      } else {
        self._verify(client, verified);
      }
    }

    var state = req.query.state;
    try {
      var arity = self._stateStore.verify.length;
      if (arity == 4) {
        self._stateStore.verify(req, state, meta, loaded);
      } else { // arity == 3
        self._stateStore.verify(req, state, loaded);
      }
    } catch (ex) {
      return self.error(ex);
    }
  }
};

/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
