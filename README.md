## Overview
`EST_Service` is a lightweirght Python-based implementation of the Enrollment over Secure Transport (EST) protocol, designed for cost-effective and automated IoT device enrollment in AWS environments. It uses an API Gateway with HTTPS, and an AES Key Pair for secure, scalable, and efficient device provisioning service.
### How This EST Implementation Works
- **Cost-Effective HTTPS**: Secure transport while minimizing TLS certificate expenses.
- **AWS Lambda Deployment**: Automates the enrollment of IoT devices in AWS IoT Core.
- **API Gateway**: Provides a scalable, managed entry point for EST requests.
- **Automated Certificate Provisioning**: Devices securely request and receive certificates automatically.
### Why Use This Over a GUI?
- **Cheaper & Efficient**: Cost-efficient with high security.
- **Fully Automated**: No manual device enrollment.
- **Scales Easily**: Handles large numbers of devices in AWS.
- **Lightweight & Headless**: CLI-based, ideal for embedded IoT devices.
### Components & Deployment
- **Terraform**: Required for infrastructure setup.
- **Server (API Gateway + Lambda)**: Manages device enrollment securely over HTTPS.
- **Client (client.py)**: Runs on IoT devices to securely communicate with the EST server.
- **AWS IoT Core**: Manages device registration and certificates.

<img src="https://raw.githubusercontent.com/actuallypav/EST_Service/refs/heads/main/img/EST-certificate-enrollement.png" alt="Smiley Picture" width="1000"/>

### `client_config.json`
The `client_config.json` file configures the client (IoT device) for EST communication. Here's an example:
```json
{
  "ESTDetails": {
    "ESTAPIURL": "https://your-api-url.example.com",
    "Region": "your-aws-region",
    "KV_Name": "your-secret-key-name"
  },
  "Devices": [
    {
      "IoTDetails": {
        "ThingName": "DeviceAlpha",
        "Policies": {
          "Connect": true,
          "Publish": true,
          "Receive": null,
          "Subscribe": null
        },
        "Topics": {
          "Connect": {
            "Name1": "connect/topic/*"
          },
          "Publish": {
            "Name1": "publish/topic1"
          },
          "Receive": {
            "Name1": "receive/topic1",
            "Name2": "receive/topic2"
          },
          "Subscribe": {
            "Name1": "subscribe/topic1",
            "Name2": "subscribe/topic2"
          }
        }
      }
    },
    {
      "IoTDetails": {
        "ThingName": "DeviceBeta",
        "Policies": {
          "Connect": true,
          "Publish": true,
          "Receive": null,
          "Subscribe": null
        },
        "Topics": {
          "Connect": {
            "Name1": "connect/topic/*"
          },
          "Publish": {
            "Name1": "publish/topic1"
          },
          "Receive": {
            "Name1": "receive/topic1",
            "Name2": "receive/topic2"
          },
          "Subscribe": {
            "Name1": "subscribe/topic1",
            "Name2": "subscribe/topic2"
          }
        }
      }
    }
    // Add more devices as needed
  ]
}
```
- **Devices** is a list, this allows the client to call the EST Service API multiple times to enroll multiple devices at a time - and save each unique key in it's own directory.
- **Topic Prefixes**: For the `Connect` policy, topics must be prefixed with `client/` (e.g., `client/Connect1`). Other policies (`Publish`, `Receive`, `Subscribe`) should use the `topic/` prefix.
- **IoTDetails**: Contains device-specific information, including policies and topics to interact with.
- **Policies**: `true` = Allow, `False` = Deny, `null` = do not include in policy.
This configuration is sent with the CSR to the EST server, which creates and configures the IoT device in AWS IoT Core.
### Usage
1. Create a `terraform.tfvars` with the values used in `variables.tf`
2. Deploy AWS resources using Terraform.
3. Update `client_config.json` with your device details.
4. Run `client.py` on IoT devices to request certificates and register with AWS IoT Core.
### Future Updates
1. [✓] Handle multiple device enrollment, by expanding the client_config.json functionality
3. [✓] Addition of mTLS over AES encryption
4. [✓] Automatic certificate rotation
