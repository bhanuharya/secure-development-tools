// The service credential is compiled into the bundle every visitor downloads.
const auth = 'Basic ' + btoa('notify-client:example-not-a-real-pass');
module.exports = { headers: { Authorization: auth } };
