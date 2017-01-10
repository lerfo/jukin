var UserModel  = require('../../models').User;
var User       = require('../../proxy').User;
var tools      = require('../../common/tools');
var authMiddleWare = require('../../middlewares/auth');
var eventproxy = require('eventproxy');
var validator  = require('validator');
var _          = require('lodash');
var jwt        = require('jwt-simple');
var redisClient = require('../../common/redis');
var config     = require('../../config');

// 非登录用户直接屏蔽
var auth = function (req, res, next) {
  var ep = new eventproxy();
  ep.fail(next);

  var accessToken = String(req.body.accesstoken || req.query.accesstoken || '');
  accessToken = validator.trim(accessToken);

  UserModel.findOne({accessToken: accessToken}, ep.done(function (user) {
    if (!user) {
      res.status(401);
      return res.send({success: false, error_msg: '错误的accessToken'});
    }
    if (user.is_block) {
      res.status(403);
      return res.send({success: false, error_msg: '您的账户被禁用'});
    }
    req.user = user;
    next();
  }));

};

exports.auth = auth;

// 非登录用户也可通过
var tryAuth = function (req, res, next) {
  var ep = new eventproxy();
  ep.fail(next);

  var accessToken = String(req.body.accesstoken || req.query.accesstoken || '');
  accessToken = validator.trim(accessToken);

  UserModel.findOne({accessToken: accessToken}, ep.done(function (user) {
    if (!user) {
      return next()
    }
    if (user.is_block) {
      res.status(403);
      return res.send({success: false, error_msg: '您的账户被禁用'});
    }
    req.user = user;
    next();
  }));

};

exports.tryAuth = tryAuth;


exports.signup = function (req, res, next) {
  if ([req.body.loginname, req.body.pass, req.body.rePass, req.body.email].some(function (item) { return item === ''; })) {
    ep.emit('prop_err', '信息不完整。');
    return;
  }
  var loginname = validator.trim(req.body.loginname || '').toLowerCase();
  var email     = validator.trim(req.body.email || '').toLowerCase();
  var pass      = validator.trim(req.body.pass || '');
  var rePass    = validator.trim(req.body.re_pass || '');

  var ep = new eventproxy();
  ep.fail(next);
  ep.on('prop_err', function (msg) {
    res.status(422);
    res.send({success: false, error_msg: msg, loginname: loginname, email: email});
  });

  // 验证信息的正确性
  if ([loginname, pass, rePass, email].some(function (item) { return item === ''; })) {
    ep.emit('prop_err', '信息不完整。');
    return;
  }
  if (loginname.length < 5) {
    ep.emit('prop_err', '用户名至少需要5个字符。');
    return;
  }
  if (!tools.validateId(loginname)) {
    return ep.emit('prop_err', '用户名不合法。');
  }
  if (!validator.isEmail(email)) {
    return ep.emit('prop_err', '邮箱不合法。');
  }
  if (pass !== rePass) {
    return ep.emit('prop_err', '两次密码输入不一致。');
  }
  // END 验证信息的正确性


  User.getUsersByQuery({'$or': [
    {'loginname': loginname},
    {'email': email}
  ]}, {}, function (err, users) {
    if (err) {
      return next(err);
    }
    if (users.length > 0) {
      ep.emit('prop_err', '用户名或邮箱已被使用。');
      return;
    }

    tools.bhash(pass, ep.done(function (passhash) {
      // create gravatar
      var avatarUrl = User.makeGravatar(email);
      User.newAndSave(loginname, loginname, passhash, email, avatarUrl, true, function (err) {
        if (err) {
          return next(err);
        }
        // 发送激活邮件
        //mail.sendActiveMail(email, utility.md5(email + passhash + config.session_secret), loginname);
        res.send({success: true,  loginname: loginname, email: email} );
      });
    }));
  });
};

 exports.login  = function (req, res, next) {
  var ep        = new eventproxy();
  ep.fail(next);
  //console.log(req);
  if (!req.body.loginname || !req.body.pass) {
    res.status(422);
    return res.send({success: false, error_msg: '信息不完整。'} );
  }
  console.log('loginname:'+req.body.loginname+',pass:'+req.body.pass);
  var loginname = validator.trim(req.body.loginname || '').toLowerCase();
  var pass      = validator.trim(req.body.pass || '');
  console.log('loginname:'+loginname+',pass:'+pass);
  if (!loginname || !pass) {
    res.status(422);
    return res.send({success: false, error_msg: '信息不完整。'} );
  }

  var getUser;
  if (loginname.indexOf('@') !== -1) {
    getUser = User.getUserByMail;
  } else {
    getUser = User.getUserByLoginName;
  }

  ep.on('login_error', function (login_error) {
    res.status(403);
    res.send({success: false, error_msg: '用户名或密码错误'} );
  });

  getUser(loginname, function (err, user) {
    if (err) {
      return next(err);
    }
    if (!user) {
      return ep.emit('login_error');
    }
    var passhash = user.pass;
    tools.bcompare(pass, passhash, ep.done(function (bool) {
      if (!bool) {
        return ep.emit('login_error');
      }
      if (!user.active) {
        // 重新发送激活邮件
        mail.sendActiveMail(user.email, utility.md5(user.email + passhash + config.session_secret), user.loginname);
        res.status(403);
        return res.send(  {success: false, error_msg: '此帐号还没有被激活，激活链接已发送到 ' + user.email + ' 邮箱，请查收。'  });
      }
      // store token in redis
      var access_token = authMiddleWare.gen_jwtToken(user, req);
      redisClient.set(access_token, { is_expired: true });
      redisClient.expire(access_token, config.redis_jwt_token_exprie_sec);//Token 有效期30天  
      // show part of userdata
      user =_.pick(user,['loginname', 'avatar_url', 'githubUsername','create_at', 'score']);
      //
      res.status(200);
      res.send(  {success: true, token:access_token, data: user} );
    }));
  });
};

// sign out
exports.signout = function (req, res, next) {
  //TODO:cancel token
  //access_token = req.body.access_token
  var ep = new eventproxy();
  ep.fail();

  var accessToken = String(req.body.access_token || req.query.access_token || req.headers['x-access-token'] || '');
  if(!accessToken){
    res.status(401);
    return res.send({success: false, error_msg: 'accessToken不存在'});
  }

  accessToken = validator.trim(accessToken);
  redisClient.del(accessToken, ep.done(function (err, reply) {
        if (err) {
            console.log(err);
            res.status(500);
            return res.send(  {success: false} );
        }
        console.log('sucess del token :'+accessToken);
        res.status(200);
        return res.send(  {success: true} );
  }));
};


exports.updateSearchPass = function (req, res, next) {
  var email = validator.trim(req.body.email || '').toLowerCase();
  if (!validator.isEmail(email)) {
    res.status(403);
    return res.send({success: false, error_msg: '邮箱不合法', email: email} );
  }

  // 动态生成retrive_key和timestamp到users collection,之后重置密码进行验证
  var retrieveKey  = uuid.v4();
  var retrieveTime = new Date().getTime();

  User.getUserByMail(email, function (err, user) {
    if (!user) {
      res.status(403);
      return res.send({success: false, error_msg: '没有这个电子邮箱', email: email} );
    }
    user.retrieve_key = retrieveKey;
    user.retrieve_time = retrieveTime;
    user.save(function (err) {
      if (err) {
        return next(err);
      }
      // 发送重置密码邮件
      mail.sendResetPassMail(email, retrieveKey, user.loginname);
      res.status(200);
      return res.send({success: true, retrieveKey: retrieveKey, email: email} );
      //res.render('notify/notify', {success: '我们已给您填写的电子邮箱发送了一封邮件，请在24小时内点击里面的链接来重置密码。'});
    });
  });
};
/**
 * reset password
 * 'get' to show the page, 'post' to reset password
 * after reset password, retrieve_key&time will be destroy
 * @param  {http.req}   req
 * @param  {http.res}   res
 * @param  {Function} next
 */
exports.resetPass = function (req, res, next) {
  var key  = validator.trim(req.query.key || '');
  var name = validator.trim(req.query.name || '');
  // 验证信息的正确性
  if ([key, name].some(function (item) { return item === ''; })) {
    res.status(403);
    return res.send({success: false, error_msg: '信息不完整', name: name, key: key} )
  }

  User.getUserByNameAndKey(name, key, function (err, user) {
    if (!user) {
      res.status(403);
      return res.send({success: false, error_msg: '信息有误，密码无法重置', name: name});
    }
    var now = new Date().getTime();
    var oneDay = 1000 * 60 * 60 * 24;
    if (!user.retrieve_time || now - user.retrieve_time > oneDay) {
      res.status(403);
      return res.send({success: false, error_msg: 'retrieve_time已过期，请重新申请', name: name});
    }
    return res.send({success: true, name: name, key: key});
  });
};

exports.updatePass = function (req, res, next) {
  var psw   = validator.trim(req.body.psw || '') ;
  var repsw = validator.trim(req.body.repsw || '');
  var key   = validator.trim(req.body.key || '');
  var name  = validator.trim(req.body.name || '');

  var ep = new eventproxy();
  ep.fail(next);

  // 验证信息的正确性
  if ([key, name, psw, repsw].some(function (item) { return item === ''; })) {
    return res.send({success: false, error_msg: '信息不完整', name: name, key: key, psw:psw, repsw:repsw} );
  }

  if (psw !== repsw) {
    return res.send({success: false, error_msg: '两次密码输入不一致。', name: name, key: key, psw:psw, repsw:repsw} )
  }
  User.getUserByNameAndKey(name, key, ep.done(function (user) {
    if (!user) {
      return res.send({success: false, error_msg: '信息错误', name: name, key: key, psw:psw, repsw:repsw} );
    }
    tools.bhash(psw, ep.done(function (passhash) {
      user.pass          = passhash;
      user.retrieve_key  = null;
      user.retrieve_time = null;
      user.active        = true; // 用户激活

      user.save(function (err) {
        if (err) {
          return next(err);
        }
        res.send({success: true, name: name} )
      });
    }));
  }));
};


exports.tokenAuth = function (req, res, next) {
  var ep = new eventproxy();
  ep.fail(next);

  var accessToken = String(req.body.access_token || req.query.access_token || req.headers['x-access-token'] || '');
  if(!accessToken){
    res.status(401);
    return res.send({success: false, error_msg: 'accessToken不存在'});
  }

  accessToken = validator.trim(accessToken);

    var userId = authMiddleWare.verify_jwtToken(accessToken,req)
    console.log('userId:'+userId);
    //find token in redis
    console.log('accessToken:'+accessToken);
    redisClient.get(accessToken, function (err, reply) {
        if (err) {
            console.log('err:'+err+',reply:'+reply);
            return ep.emit('isTokenEffective',false);
        }
        console.log('reply:'+reply);
        if (reply) {
            return ep.emit('isTokenEffective',true);
        }
        else {
            return ep.emit('isTokenEffective',false);
        }
    });
    // handle token here
    ep.all('isTokenEffective',function (isTokenEffective) {
      console.log('isTokenEffective:'+isTokenEffective+',userId:'+userId);
      if(isTokenEffective){
        User.getUserById(userId , ep.done(function (user) {
          if (!user) {
            res.status(401);
            return res.send({success: false, error_msg: '错误的accessToken'});
          }
          if (user.is_block) {
            res.status(403);
            return res.send({success: false, error_msg: '您的账户被禁用'});
          }
          req.user = user;
          console.log('user:'+user);
          next();
        }));
      }else{
          res.status(401);
          return res.send({success: false, error_msg: '未登录'});
      }
    });



};