const splunk = require("../helpers/splunk");
module.exports = async function (context, eventHubMessages) {
  try {
    if (Array.isArray(eventHubMessages)) {
      for (const message of eventHubMessages) {
        await splunk
          .sendToHEC(message, process.env["AAD_NON_INTERACTIVE_SIGNIN_LOG_SOURCETYPE"]);
      }
    } else {
      await splunk
        .sendToHEC(eventHubMessages, process.env["AAD_NON_INTERACTIVE_SIGNIN_LOG_SOURCETYPE"]);
    }
  } catch (error) {
    context.log.error(`Error processing aad-signin-logs-non-interactive ${error}`);
  }
};