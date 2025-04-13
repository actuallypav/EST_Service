### Overview
`EST_Service` is a Python-based implementation of the Enrollment over Secure Transport (EST) protocol, designed for cost-effective and automated IoT device enrollment in AWS environments. It uses an API Gateway and HTTPS for secure, scalable, and efficient device provisioning.

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

### `client_config.json`
The `client_config.json` file configures the client (IoT device) for EST communication. Here's an example:

```json
{
    "ESTDetails": {
        "ESTAPIURL": "https://your-est-server-url",
        "Region": "eu-west-2",
        "KV_Name": "AES_kv"
    },
    "IoTDetails": {
        "ThingName": "Megatron",
        "Policies": {
            "Connect": true,
            "Publish": null,
            "Receive": false,
            "Subscribe": false
        },
        "Topics": {
            "Connect": {
                "Name1": "client/Connect1",
                "Name2": "client/Connect2"
            },
            "Publish": {
                "Name1": "topic/Publish1",
                "Name2": "topic/Publish2"
            },
            "Receive": {
                "Name1": "topic/Receive1",
                "Name2": "topic/Receive2"
            },
            "Subscribe": {
                "Name1": "topic/Subscribe1",
                "Name2": "topic/Subscribe2"
            }
        }
    }
}
```

- **Topic Prefixes**: For the `Connect` policy, topics must be prefixed with `client/` (e.g., `client/Connect1`). Other policies (`Publish`, `Receive`, `Subscribe`) should use the `topic/` prefix.
- **IoTDetails**: Contains device-specific information, including policies and topics to interact with.
- **Policies**: `true` = Allow, `False` = Deny, `null` = do not include in policy.

This configuration is sent with the CSR to the EST server, which creates and configures the IoT device in AWS IoT Core.

### Usage
1. Create a `terraform.tfvars` with the values used in `variables.tf`
2. Deploy AWS resources using Terraform.
3. Update `client_config.json` with your device details.
4. Run `client.py` on IoT devices to request certificates and register with AWS IoT Core.
