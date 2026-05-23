# Identity Provider (IAM) Service

This package provides a robust, zero-trust Identity and Access Management (IAM) service. It integrates authentication, authorization, and automated lifecycle management (SCIM) into a single, modular system designed for mesh-native environments.

## Architecture

This service is built on three core pillars:

* **`secure_bootstrap`**: Handles user authentication via hardware-backed Passkeys and establishes secure session bindings.
* **`secure_policy`**: Manages Attribute-Based Access Control (ABAC/PBAC) to govern what users and machines can access across the mesh.
* **`secure_networking`**: Provides the encrypted transport layer (Noise protocol over QUIC) and event-driven RPC mechanisms to propagate state across the edge nodes.

## Key Features

* **Event-Driven SCIM Provisioning**: Asynchronous lifecycle management ensures that when a user is assigned to an application, accounts are automatically provisioned in downstream systems without blocking the UI.
* **Zero-Trust Middleware**: Enforces access policy checks at the router level, ensuring that every request is evaluated against the `secure_policy` engine.
* **Admin Controller**: A unified management layer for registering applications, assigning user access, and auditing security events.
* **Identity Context**: Unified `Identity` struct that seamlessly bridges human (Passkey) and service (Noise static key) identities.

## Getting Started

### 1. Register an Application

Use the `AdminController` to define your application and its required policy:

```go
app := Application{
    ID:           "app_123",
    Name:         "Internal Dashboard",
    SCIMEndpoint: "https://api.target.app/scim",
    SCIMToken:    "your-bearer-token",
}
admin.RegisterApp(app)

```

### 2. Enforce Policy

Protect your routes using the built-in middleware:

```go
r.Mux.HandleFunc("/secure-data", EnforcePolicy(policyEngine, "read", "data_resource")(func(w http.ResponseWriter, r *http.Request) {
    w.Write([]byte("Authorized Content"))
}))

```

## Testing

The package includes a comprehensive test suite (`identity_provider_test.go`) that validates the entire lifecycle:

* **Lifecycle**: Confirms app registration and user assignment logic.
* **Provisioning**: Uses a mock transport to verify that SCIM `POST` requests are correctly formatted and dispatched asynchronously.
* **Middleware**: Verifies that requests without valid session cookies or insufficient policy permissions are correctly rejected.

To run the tests:

```bash
go test -v ./...

```

---

*Developed as part of the Zero-Trust IAM suite.*
