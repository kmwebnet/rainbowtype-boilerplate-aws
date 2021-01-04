const AWS = require("aws-sdk");

const REGION = "us-east-1";

const iotClient = new AWS.Iot({
  region: REGION,
  apiVersion: "2015-05-28"
});

exports.handler = async event => {
  const accountId = event.awsAccountId.toString().trim();
  const certificateId = event.certificateId.toString().trim();
  const certificateARN = `arn:aws:iot:${REGION}:${accountId}:cert/${certificateId}`;
  const policyName = `Policy_${certificateId}`;

  const policy = {
    Version: "2012-10-17",
    Statement: [
      {
        "Effect": "Allow",
        "Action": [
          "iot:Connect",
          "iot:Publish",
          "iot:Receive",
          "iot:Subscribe"
        ],
        "Resource": [
          "*"
        ]
      }
    ]
  };

  await iotClient
    .createPolicy({
      policyDocument: JSON.stringify(policy),
      policyName: policyName
    })
    .promise();

  await iotClient
    .attachPrincipalPolicy({
      policyName: policyName,
      principal: certificateARN
    })
    .promise();

  await iotClient
    .updateCertificate({
      certificateId: certificateId,
      newStatus: "ACTIVE"
    })
    .promise();
};