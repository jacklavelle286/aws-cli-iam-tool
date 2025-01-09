# AWS CLI IAM Tool

## Description
The **AWS CLI IAM Tool** simplifies the management of AWS Identity and Access Management (IAM) policies, users, roles, and groups. Writing JSON policy documents manually can be tedious and error-prone when using the AWS CLI. This tool provides an intuitive, Python-based wrapper to make IAM management faster and easier.

While currently a Python program, the tool is being developed into a full-fledged Command Line Interface (CLI) application that can be installed and run like any other Python package.

---

## Features

### IAM Policies
- **Create IAM Policies**:
  - Guided prompts for defining policy details such as SID, effect, actions, and resources.
  - Supports multiple `Statement` blocks interactively.
  - Saves policies as JSON files locally and creates them directly in AWS.
  
- **List IAM Policies**:
  - View all customer-managed policies in AWS.
  - List locally stored policies for easy management.

- **Delete IAM Policies**:
  - Delete a specific local policy file or all local policy files at once.
  - Detach and delete policies directly in AWS.

### IAM Users
- **Create IAM Users**:
  - Guided input to create new IAM users.
  - Optionally assign policies or add users to groups during creation.

- **List IAM Users**:
  - Retrieve a list of all existing IAM users with detailed attributes.

- **Delete IAM Users**:
  - Remove users interactively or in bulk, ensuring associated resources (e.g., policies) are detached.

### IAM Groups
- **Create IAM Groups**:
  - Easily create groups and attach policies.

- **List IAM Groups**:
  - View all existing groups and their associated policies.

- **Delete IAM Groups**:
  - Safely delete groups and associated resources.

### IAM Roles
- **Create IAM Roles**:
  - Define trust relationships and attach policies through guided input.

- **List IAM Roles**:
  - Retrieve all roles and their details.

- **Delete IAM Roles**:
  - Remove roles safely, ensuring associated resources are detached.

---

## Problem Statement
Managing IAM resources using the AWS CLI can be complex and time-consuming, especially when writing and managing JSON policy documents manually. The **AWS CLI IAM Tool** solves these problems by:
- Providing an interactive interface for creating and managing IAM resources.
- Automating the generation and validation of JSON policy documents.
- Reducing the time, effort, and errors associated with managing IAM.

---

## Future Vision
The tool is being developed into a fully-fledged CLI application with:
- Installation via `pip` (`pip install aws-cli-iam-tool`).
- Subcommands for managing IAM resources (`iam-tool policy create`, `iam-tool user list`, etc.).
- Enhanced error handling and input validation.
- Tab-completion for easier navigation.

---




