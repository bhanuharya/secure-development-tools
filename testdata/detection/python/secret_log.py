import logging

logger = logging.getLogger(__name__)


# The password is written to the log.
def login(username, password):
    logger.info("login attempt %s %s", username, password)
