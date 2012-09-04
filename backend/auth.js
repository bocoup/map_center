var _ = require("underscore");
var express = require("express");
var RedisStore = require("connect-redis")(express);
var passport = require("passport");
var TwitterStrategy = require("passport-twitter").Strategy;
var GoogleStrategy = require("passport-google-oauth").OAuth2Strategy;

// Dynamically generating a secret in this way means one less file will have to
// be managed outside of the repository. The drawback is that, in the event of
// a server re-start, all authenticated users will be kicked and need to re-
// authenticate.
var sessionSecret = "This is a secret." + Math.random();
var cookieParsers = {
    insecure: express.cookieParser(),
    secure: express.cookieParser(sessionSecret)
};
var sessionStore = new RedisStore();

passport.serializeUser(function(user, done) {
    done(null, user.id);
});
passport.deserializeUser(function(id, done) {
    // For now, don't bother persisting information about the user. Simply set
    // a flag so the application can grant access to recognized users.
    done(null, { id: id });
});

exports.initialize = function(serviceLocation, CREDS) {

    var serviceBaseUrl = "http://" + serviceLocation.hostName + ":" +
        serviceLocation.portNumber;

    function authorize(isRecognized, id, done) {
        if (isRecognized) {
            return done(null, { id: id, isRecognized: true });
        } else {
            return done("Not recognized");
        }
    }

    passport.use(new TwitterStrategy({
            consumerKey: CREDS.oauth.twitter.key,
            consumerSecret: CREDS.oauth.twitter.secret,
            callbackURL: serviceBaseUrl + "/auth/twitter/callback"
        },
        function(token, tokenSecret, profile, done) {

            var id = profile.username;
            var isRecognized = CREDS.oauth.twitter.ids.indexOf(id) > -1;

            authorize(isRecognized, id, done);

        }
    ));

    passport.use(new GoogleStrategy({
            clientID: CREDS.oauth.google.key,
            clientSecret: CREDS.oauth.google.secret,
            callbackURL: serviceBaseUrl + "/auth/google/callback"
        },
        function(accessToken, refreshToken, profile, done) {

            // profile.emails is an array with the following format:
            // [ { value: "a@b.com" }, { value: "c@d.com" }, ... ]
            // So _.pluck out the e-mail addresses themselves.
            var emailAddresses = _.pluck(profile.emails, "value");
            var ids = _.intersection(CREDS.oauth.google.ids, emailAddresses);
            var id = ids[0];
            var isRecognized = (id !== undefined);

            authorize(isRecognized, id, done);
        }
    ));

};
// Extend the specified Express application with the necessary middleware for
// authentication
exports.extendApp = function(app) {

    // Simple Connect middleware to restrict access from unauthorized users
    var redirectUnauthorized = function(req, res, next) {
        // Certain pages should be accessible to anyone, namely: the index
        // (login) page and the authorization pages
        if (req.path === "/" || req.path === "/logout" || /^\/auth\//.test(req.path) ||
            // All other pages should only be served to users that have
            // properly authenticated
            (req.session && req.session.passport && req.session.passport.user)) {
            next();

        // In any other case, deny the request
        } else {
            next("Unauthorized");
        }
    };

    app.use(cookieParsers.insecure);
    app.use(express.session({
        store: sessionStore,
        secret: sessionSecret
    }));
    app.use(passport.initialize());
    app.use(passport.session());
    app.use(redirectUnauthorized);
    app.use(express.static(__dirname + "/www"));

    app.get("/auth/twitter", passport.authenticate("twitter"));
    app.get("/auth/twitter/callback",
        passport.authenticate("twitter", {
            successRedirect: "/",
            failureRedirect: "/"
        }));

    app.get("/auth/google", passport.authenticate("google", {
        scope: [
            "https://www.googleapis.com/auth/userinfo.profile",
            "https://www.googleapis.com/auth/userinfo.email"
        ]}));
    app.get("/auth/google/callback",
        passport.authenticate("google", {
            successRedirect: "/",
            failureRedirect: "/"
        }));
    app.get("/logout", function(req, res) {
        req.logOut();
        req.session.destroy(function(err) {
            res.redirect("/");
        });
    });
};
exports.checkSession = function(cookie, callback) {
    // Use the cookie string from the handshake data to construct a request
    // object for use with the cookieParser middleware.
    var fakeReq = { headers: { cookie: cookie } };

    cookieParsers.secure(fakeReq, {}, function(err) {

        var sessionId = fakeReq.signedCookies["connect.sid"];

        sessionStore.get(sessionId, function(err, data) {

            var isAuthorized;

            if (err) {
                return callback(err);
            }
            isAuthorized = !!(data && data.passport && data.passport.user);

            callback(null, isAuthorized);
        });
    });

};
