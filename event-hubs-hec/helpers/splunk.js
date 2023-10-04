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
axios.interceptors.request.use((request) => {
  // console.log('Starting Request', JSON.stringify(request, null, 2))
  return request;
});
axios.interceptors.response.use((response) => {
  // console.log('Response:', response)
  return response;
});

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

const getComputerName = function (message) {
  if (message.hasOwnProperty("Computer")) {
    return message["Computer"];
  }
  return null;
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
  if (message.hasOwnProperty("time")) {
    return getEpochTime(message["time"]);
  }
  return null;
};

const getSource = function (message) {
  if (message.hasOwnProperty("SourceSystem")) {
    return message["SourceSystem"];
  } else if (message.hasOwnProperty("Source")) {
    return message["Source"];
  } else {
    return "Azure";
  }
};

const getEventString = function (record) {
  eventclean = record["EventData"].replace(
    "http://schemas.microsoft.com/win/2004/08/events/event",
    ""
  );
  eventclean = eventclean.replace("xmlns=", "");
  eventclean = eventclean.replace("'", "");
  eventclean = eventclean.replace("''", "");  

  eventString = `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='${record["Source"]}'/><EventID Qualifiers='${record["EventCategory"]}'>${record["EventID"]}</EventID><Level>${record["EventLevel"]}</Level><TimeCreated SystemTime='${record["TimeGenerated"]}'/><Channel>${record["EventLog"]}</Channel><Computer>${record["Computer"]}</Computer><Security UserID='${record["UserName"]}'/></System><EventData>${eventclean}</EventData></Event>`;

  return eventString;
};

const sendToHEC = function (message, sourcetype) {
  let headers = {
    Authorization: `Splunk ${process.env["SPLUNK_HEC_TOKEN"]}`,
    "content-Type": "application/json",
  };

  let payload = "";

  try {
    jsonMessage = JSON.parse(message);
  } catch (err) {
      // The message is not JSON, so send it as-is.
      let payload = {
          "sourcetype": sourcetype,
          "source": "Azure",
          "event": message
      }
      try {
        axios.post(process.env["SPLUNK_HEC_URL"], payload, {headers: headers,
          httpsAgent: new (require('https').Agent)({ rejectUnauthorized: false }),});         
      } catch (error) {
        console.error(
          `Error sending message to Splunk: ${error} message: ${payload} `
        );
      }
      return;
  }

  // If the JSON contains a records[] array, batch the events for HEC.
  if (jsonMessage.hasOwnProperty("records")) {
    jsonMessage.records.forEach(async function (record) {

      let recordEvent = {
        sourcetype: sourcetype,
      };
      
      let computerName = getComputerName(record);
      if (computerName) {
        recordEvent["host"] = computerName;
      }

      let eventTimeStamp = getTimeStamp(record);
      if (eventTimeStamp) {
        recordEvent["time"] = eventTimeStamp;
      }

      if (
        record.hasOwnProperty("resourceId") &&
        record.hasOwnProperty("category")
      ) {
        // Get the sourcetype
        recordEvent["sourcetype"] = getSourceType(
          sourcetype,
          record.resourceId,
          record.category
        );
      }

      // If this is a WinEventLog, set the host, index, source, sourcetype, and event fields
      // Else if is a linux machine
      if (
        record.hasOwnProperty("Computer") &&
        record.hasOwnProperty("EventData") &&
        record.hasOwnProperty("EventLog")
      ) {
        // Windows Logs
        recordEvent["host"] = record["Computer"];
        recordEvent["index"] =
          record["EventLog"] == "Security"
            ? "wineventlog_security"
            : "wineventlog";
        recordEvent["source"] = `${"WinEventLog"}:${record["EventLog"]}`;
        recordEvent["sourcetype"] = "XmlWinEventLog";

        // Call the function to Build the event string
        recordEvent["event"] = getEventString(record).replace(/"/g, "'");
      } else if (
        record.hasOwnProperty("HostName") &&
        record.hasOwnProperty("SourceSystem") &&
        record.hasOwnProperty("SyslogMessage")
      ) {
        // Linux Logs
        recordEvent["host"] = record["Computer"];
        recordEvent["index"] = "os";
        //if this or that
        if (
          record["ProcessName"] == "audit-log" ||
          record["ProcessName"] == "audit_log" ||
          record["ProcessName"] == "auditd"
        ) {
          recordEvent["sourcetype"] = "linux_secure";
        } else {
          recordEvent["sourcetype"] = "linux_messages_syslog";
        }
        recordEvent["source"] = "linux_syslog";
        recordEvent["event"] = record["SyslogMessage"].replace(/"/g, "'");
      } else {
        recordEvent["event"] = JSON.stringify(record);
        let source = getSource(record);
        if (source) {
          recordEvent["source"] = source;
        }
      }

      payload = JSON.stringify(recordEvent);
      try {
        await axios
          .post(process.env["SPLUNK_HEC_URL"], payload, {
            headers: headers,
            httpsAgent: new (require("https").Agent)({
              rejectUnauthorized: false,
            }),
          })
          .then((resp) => {
            console.log(`response from splunk ${resp.status}`);
          })
          .catch((err) => {
            console.log(`error from splunk ${err}`);
          });
      } catch (error) {
        console.error(
          `Error sending message to Splunk: ${error} message: ${payload} `
        );
      }
    });
    return;
  } else {
    // If we made it here, the JSON does not contain a records[] array, so send the data as-is
    let payload = {
      sourcetype: sourcetype,
      event: JSON.stringify(message),
      source: "Azure",
    };
    try {
      axios.post(process.env["SPLUNK_HEC_URL"], payload, {
        headers: headers,
        httpsAgent: new (require("https").Agent)({ rejectUnauthorized: false }),
      });
    } catch (error) {
      console.error(
        `Error sending message to Splunk: ${error} message: ${payload} `
      );
    }
  }
};

exports.sendToHEC = sendToHEC;
