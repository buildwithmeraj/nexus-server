const fs = require("fs");
const key = fs.readFileSync(
  "./nexus-ed400-firebase-adminsdk-fbsvc-4cd65fc7ce.json",
  "utf8"
);
const base64 = Buffer.from(key).toString("base64");
console.log(base64);
