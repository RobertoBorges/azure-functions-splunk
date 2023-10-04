const splunk = require("../helpers/splunk");
module.exports = async function (context, eventHubMessages) {
  try {
    if (Array.isArray(eventHubMessages)) {
      for (const message of eventHubMessages) {
        await splunk
          .sendToHEC(message, process.env["ACTIVITY_LOG_SOURCETYPE"]);
      }
    } else {
      await splunk
        .sendToHEC(eventHubMessages, process.env["ACTIVITY_LOG_SOURCETYPE"]);
    }
  } catch (error) {
    context.log.error(`Error processing activity-logs ${error}`);
  }
};
