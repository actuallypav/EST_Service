**EST_Service**

### Overview
EST_Service is a Python-based implementation of the Enrollment over Secure Transport (EST) protocol (RFC 7030), designed for cost-effective and automated IoT device enrollment in AWS environments. This deployment is optimized for low-cost, scalable, and efficient device provisioning using an API Gateway and AES encryption to avoid HTTPS certificate costs.

### How This EST Implementation Works
- **No HTTPS Overhead:** Uses AES encryption instead of HTTPS to reduce TLS certificate costs.
- **AWS Lambda Deployment:** Automates the creation and enrollment of IoT devices ("things") in AWS IoT Core.
- **API Gateway for Cost Efficiency:** Unlike ALBs or NLBs, API Gateway provides a scalable and managed entry point for EST requests.
- **Automated Certificate Provisioning:** IoT devices securely request and receive certificates, eliminating manual setup.

### Why Use This Over a GUI?
- **Cheaper & Efficient:** Avoids unnecessary AWS costs while maintaining security.
- **Fully Automated:** No manual enrollment—devices register and get certificates on their own.
- **Scales Easily:** Works with large numbers of devices in AWS without performance bottlenecks.
- **Lightweight & Headless:** CLI-based, perfect for embedded IoT devices.

### Components & Deployment
- **Terraform Required:** Infrastructure is built using Terraform—install it first.
- **Server (API Gateway + Lambda):** API Gateway routes requests to a Lambda function, handling device enrollment.
- **Client (client.py):** Runs on each IoT device, encrypting requests and communicating with the EST server.
- **AWS IoT Core Integration:** The Lambda function registers devices and manages certificates in AWS.

### Usage
1. Deploy AWS resources using Terraform.
2. Run `client.py` on IoT devices to securely request certificates.
3. The archive folder contains legacy code and is not needed. See the repo for full details.

<img src="/img/EST-certificate-enrollement.png" alt="*Source: Sectigo*">
<sup><sub>Source: Sectigo</sub></sup>
