/*
Copyright 2020 Splunk Inc. 

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
const axios = require("axios");

// Enable the following code in order to Debug the HEC payload
// axios.interceptors.request.use(request => {
//   console.log('Starting Request', JSON.stringify(request, null, 2))
//   return request
// });
// axios.interceptors.response.use(response => {
//   console.log('Response:', response)
//   return response
// });

const getSourceType = function (sourcetype, resourceId, category) {
  // If this is an AAD sourcetype, append the category to the sourcetype and return
  let aadSourcetypes = [
    process.env["AAD_LOG_SOURCETYPE"],
    process.env["AAD_NON_INTERACTIVE_SIGNIN_LOG_SOURCETYPE"],
    process.env["AAD_SERVICE_PRINCIPAL_SIGNIN_LOG_SOURCETYPE"],
    process.env["AAD_PROVISIONING_LOG_SOURCETYPE"],
  ];
  if (aadSourcetypes.indexOf(sourcetype) > -1) {
    return `${sourcetype}:${category.toLowerCase()}`;
  }

  // Set the sourcetype based on the resourceId
  let sourcetypePattern = /PROVIDERS\/(.*?\/.*?)(?:\/)/;
  try {
    let st = resourceId
      .match(sourcetypePattern)[1]
      .replace("MICROSOFT.", "azure:")
      .replace(".", ":")
      .replace("/", ":")
      .toLowerCase();
    return `${st}:${category.toLowerCase()}`;
  } catch (err) {
    // Could not detrmine the sourcetype from the resourceId
    return sourcetype;
  }
};

const getEpochTime = function (timeString) {
  try {
    let epochTime = new Date(timeString).getTime();
    return epochTime;
  } catch {
    return null;
  }
};

const getTimeStamp = function (message) {
  if (message.hasOwnProperty("TimeGenerated")) {
    return getEpochTime(message["TimeGenerated"]);
  }
  return null;
};

const getComputerName = function (message) {
  if (message.hasOwnProperty("Computer")) {
    return message["Computer"];
  }
  return null;
};

const getHECPayload = async function (message, sourcetype) {
  try {
    jsonMessage = JSON.parse(message);
  } catch (err) {
    // The message is not JSON, so send it as-is.
    return {
      sourcetype: sourcetype,
      event: message,
    };
  }

  // If the JSON contains a records[] array, batch the events for HEC.
  if (jsonMessage.hasOwnProperty("records")) {
    let payload = jsonMessage.records.map(record => {
      let recordEvent = {
        sourcetype: sourcetype
      };

      if (record.hasOwnProperty("resourceId") && record.hasOwnProperty("category")) {
        // Get the sourcetype
        recordEvent["sourcetype"] = getSourceType(sourcetype, record.resourceId, record.category);
      }

      // If this is a WinEventLog, set the host, index, source, sourcetype, and event fields
      if (record.hasOwnProperty("Computer") && record.hasOwnProperty("EventData") && record.hasOwnProperty("EventLog")) {
        recordEvent["host"] = record["Computer"];
        recordEvent["index"] = record["EventLog"] == "Security" ? "wineventlog_security" : "wineventlog";
        recordEvent["source"] = `${"WinEventLog"}:${record["EventLog"]}`;
        recordEvent["sourcetype"] = record["XmlWinEventLog"];
        recordEvent["event"] = record["EventData"].replace(/"/g, "'");
      } else {
        recordEvent["event"] = JSON.stringify(record).replace(/\\"/g, "'");
      }

      let computerName = getComputerName(record);
      if (computerName) {
        recordEvent["host"] = computerName;
      }

      let eventTimeStamp = getTimeStamp(record);
      if (eventTimeStamp) {
        recordEvent["eventTimeStamp"] = eventTimeStamp;
      }

      return JSON.stringify(recordEvent).replace(/\\"/g, "'");
    }).join("");
    return payload;
  }

  // If we made it here, the JSON does not contain a records[] array, so send the data as-is
  let payload = {
    sourcetype: sourcetype,
    event: JSON.stringify(jsonMessage),
  };
  let eventTimeStamp = getTimeStamp(jsonMessage);
  if (eventTimeStamp) {
    payload["eventTimeStamp"] = eventTimeStamp;
  }
  return payload;
};

const sendToHEC = async (message, sourcetype) => {
  payload = "";
  try {
    const headers = {
      Authorization: `Splunk ${process.env.SPLUNK_HEC_TOKEN}`,
      "content-Type": "application/json",
    };

    let payload = await getHECPayload(message, sourcetype);
    payload = payload.replace(/\\"/g, "'");

    await axios.post(process.env.SPLUNK_HEC_URL, payload, {
      headers,
      httpsAgent: new (require('https').Agent)({ rejectUnauthorized: false }),
    });

    console.log(`message sent, original message: ${message} sourcetype: ${sourcetype} payload: ${payload}`);
  } catch (error) {
    console.error(`Error sending message to Splunk: ${error} message: ${message} sourcetype: ${sourcetype} payload: ${payload}`);
  }
};

exports.sendToHEC = sendToHEC;
