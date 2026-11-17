// The login form writes the password to the browser console.
function handleSubmit(username, password, rememberMe) {
  console.log('in handle submit: ' + username + ':' + password + ':' + rememberMe);
  return { username, rememberMe };
}
module.exports = { handleSubmit };
