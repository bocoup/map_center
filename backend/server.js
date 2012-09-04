var fs = require("fs");
var http = require("http");
var express = require("express");
var app = express();
var server = http.createServer(app);
var _ = require("underscore");

var BroadcastSchedule = require("./broadcastSchedule");

// Server name and port. Reference environmental variables when they are set,
// and fall back to sensible defaults.
var serviceLocation = {
    portNumber: process.env.NODE_PORT || 8000,
    hostName: process.env.NODE_HOST || "127.0.0.1"
};

// Credentials, stored in non-version-controlled files
var CREDS = {
    oauth: {
        twitter: require("./credentials/oauth/twitter.json"),
        google: require("./credentials/oauth/google.json")
    },
    ssl: {
        key: fs.readFileSync("./credentials/ssl/privatekey.pem").toString(),
        cert: fs.readFileSync("./credentials/ssl/certificate.pem").toString()
    }
};

var broadcastSchedule = new BroadcastSchedule();

// ----------------------------------------------------------------------------
// --[ scheduling control HTTP endpoints ]


app.configure(function() {
    app.use(express.bodyParser());
});

var auth = require("./auth");
auth.initialize(serviceLocation, CREDS);
auth.extendApp(app);
require("./routes")(app, broadcastSchedule);
require("./broadcaster")(server, broadcastSchedule);

server.listen(serviceLocation.portNumber, serviceLocation.hostName);
