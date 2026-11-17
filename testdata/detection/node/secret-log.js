// The one-time code is written to the server log.
function sendOtp(logger, username, otp) {
  logger.info(`otp for ${username} is ${otp}`);
}
