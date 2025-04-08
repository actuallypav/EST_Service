**EST_Service**

### Overview
EST_Service is a Python-based implementation of the Enrollment over Secure Transport (EST) protocol, designed for cost-effective and automated IoT device enrollment in AWS environments. This deployment is optimized for scalable and efficient device provisioning using an API Gateway and HTTPS encryption to ensure security while minimizing costs.

### How This EST Implementation Works
- **Cost-Effective HTTPS:** Utilizes HTTPS for secure transport while minimizing TLS certificate expenses.
- **AWS Lambda Deployment:** Automates the creation and enrollment of IoT devices ("things") in AWS IoT Core.
- **API Gateway for Cost Efficiency:** Unlike ALBs or NLBs, API Gateway provides a scalable and managed entry point for EST requests.
- **Automated Certificate Provisioning:** IoT devices securely request and receive certificates, eliminating manual setup.

### Why Use This Over a GUI?
- **Cheaper & Efficient:** Optimized for cost efficiency while maintaining security.
- **Fully Automated:** No manual enrollment — devices register and get certificates on their own.
- **Scales Easily:** Works with large numbers of devices in AWS without performance bottlenecks.
- **Lightweight & Headless:** CLI-based, perfect for embedded IoT devices.

### Components & Deployment
- **Terraform Required:** Infrastructure is built using Terraform — install it first.
- **Server (API Gateway + Lambda):** API Gateway routes requests to a Lambda function, handling device enrollment securely over HTTPS.
- **Client (client.py):** Runs on each IoT device, encrypting requests and communicating with the EST server.
- **AWS IoT Core Integration:** The Lambda function registers devices and manages certificates in AWS.
- **Requires the creation of a variables file - or manual entry.

### Usage
1. Deploy AWS resources using Terraform.
2. Run `client.py` on IoT devices to securely request certificates.

<img src="/img/EST-certificate-enrollement.png" alt="*Source: Sectigo*">

