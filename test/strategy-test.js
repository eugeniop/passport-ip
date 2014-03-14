var vows = require('vows');
var assert = require('assert');
var util = require('util');
var Strategy = require('passport-ip/strategy');
var BadRequestError = require('passport-ip/errors/badrequesterror');


vows.describe('ipStrategy').addBatch({
  
  'strategy': {
    topic: function() {
      return new Strategy({range:'1.1.1.1'}, function(){});
    },
    
    'should be named session': function (strategy) {
      assert.equal(strategy.name, 'ip');
    },
  },
  
  'strategy handling a request in range': {
    topic: function() {
      var strategy = new Strategy({range:'1.1.1.1/5'}, function(){});
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};

        strategy.success = function(user) {
          self.callback(null, user);
        }

        strategy.fail = function() {
          self.callback(new Error('should-not-be-called'));
        }
        
        strategy._verify = function(client, done) {
          done(null, { user_id: client.id });
        }
        
        req.headers = { 'X-Forwarded-For': '1.1.1.1'};
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not generate an error' : function(err, user) {
        assert.isNull(err);
      },
      'should authenticate' : function(err, user) {
        assert.equal(user.id, '1.1.1.1');
      },
    },
  },
  
  'strategy handling a request off range fails': {
    topic: function() {
      var strategy = new Strategy({range:'1.1.1.1/5'}, function(){});
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(new Error('should-not-be-called'));
        }
        strategy.fail = function() {
          self.callback(null);
        }
        
        strategy._verify = function(client, done) {
          self.callback(new Error('should-not-be-called'));
        }
        
        req.headers = { 'X-Forwarded-For': '1.1.1.6'};
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not generate an error' : function(err, user) {
        assert.isNull(err);
      },
      'should authenticate' : function(err, user) {
        assert.equal(user.username, 'johndoe');
        assert.equal(user.password, 'secret');
      },
    },
  },
  
  'strategy handling a request that encounters an error during verification': {
    topic: function() {
      var strategy = new LocalStrategy({range: '1.1.1.1/2'}, function(){});
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(new Error('should-not-be-called'));
        }
        strategy.fail = function() {
          self.callback(new Error('should-not-be-called'));
        }
        strategy.error = function(err) {
          self.callback(null, err);
        }
        
        strategy._verify = function(client, done) {
          done(new Error('something-went-wrong'));
        }
        
        req.body = {headers:{ 'X-Forwarded-For': '1.1.1.1'}};
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not call success or fail' : function(err, e) {
        assert.isNull(err);
      },
      'should call error' : function(err, e) {
        assert.instanceOf(e, Error);
      },
    },
  },
  
  'strategy handling a request with no IP address': {
    topic: function() {
      var strategy = new LocalStrategy({range:'1.1.1.1/2'}, function(){});
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.fail = function(info) {
          self.callback(null, info);
        }
        
        req.body = { headers: {} };
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should fail authentication' : function(err) {
        // fail action was called, resulting in test callback
        assert.isTrue(true);
      },
      'should pass BadReqestError as additional info' : function(err, info) {
        assert.instanceOf(info, Error);
        assert.instanceOf(info, BadRequestError);
      },
    },
  },
  
  'strategy constructed without a verify callback': {
    'should throw an error': function (strategy) {
      assert.throws(function() { new Strategy() });
    },
  },

  'strategy constructed without a range': {
    'should throw an error': function (strategy) {
      assert.throws(function() { new Strategy({something_else:'whatever'}, function(){}) });
    },
  },

}).export(module);
