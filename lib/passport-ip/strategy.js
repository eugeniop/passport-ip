/**
 * Module dependencies.
 */
var passport = require('passport')
  , util = require('util')
  , BadRequestError = require('./errors/badrequesterror')
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
  if(!verify){ throw new Error('IP authentication strategy requires a verify function'); }
  if(!options.range){ throw new Error('IP authentication strategy requires an IP Range parameter'); }

  this._range = options.range;
  
  passport.Strategy.call(this);
  this.name = 'ip';
  this._verify = verify;
  this._passReqToCallback = options.passReqToCallback;
  this._username = options.username;
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);

/**
 * Authenticate request based on the client IP address
 *
 * @param {Object} req
 * @api protected
 */
Strategy.prototype.authenticate = function(req) {

  if(!req.query.code)
  {
    //First time we force a redirect to kick-off the 2nd stage of Auth0 authN
    this.redirect('/login/callback?code=dummy');
  }
  else
  {
    //we are back from the redirect. Check the IP address
    var clientIP = req.headers['X-Forwarded-For'];

    if(!clientIP) { return this.fail(new BadRequestError("No X-Forwarded-For header.")); } 

    if(!range_check.in_range(clientIP, this._range))
    {
      return this.fail("Client IP is outside the range specified for this strategy.");
    }

    var self = this;

    function verified(err, user) {
      if (err) { return self.error(err); }
      if (!user) { return self.fail(new Error('No user in verified callback.')); }
      self.success(user);
    }
  
    var client = {
      id: clientIP
    };

    if(this._username){
      client.username = this._username;
    }

    if (self._passReqToCallback) {
      this._verify(req, client, verified);
    } else {
      this._verify(client, verified);
    }
  }    
}


/**
 * Expose `Strategy`.
 */ 
module.exports = Strategy;
