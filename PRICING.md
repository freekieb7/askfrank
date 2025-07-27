# 🏥 Healthcare SaaS Pricing Strategy

This document outlines the proposed pricing strategy for our healthcare SaaS platform that enables **patients to store and manage their own health data**, while **authorized providers can access it for a fee**. The strategy includes tiered subscription pricing, usage-based billing, and add-ons for advanced capabilities.

---

## 🔍 Overview

- **Patient-Centric Model**: Patients own their data and can grant access to providers.
- **Provider Access Model**: Providers subscribe to view and interact with patient data.
- **Flexible Billing**: Combines flat-tier pricing with usage-based billing to ensure fairness and scalability.
- **Inspired by**: Grafana’s pricing system with adaptations for healthcare-specific needs.

---

## 🧱 Tiered Pricing (Per Provider)

| Tier           | Monthly Price | Included Patients | Features                                                                 |
|----------------|---------------|--------------------|--------------------------------------------------------------------------|
| **Free**       | $0            | 3                  | View-only dashboard, limited support                                     |
| **Starter**    | $49           | 50                 | Full patient view, export reports, download data                         |
| **Pro**        | $199          | 500                | Advanced analytics, patient messaging, customizable dashboards           |
| **Enterprise** | Custom        | Unlimited          | SSO, audit logs, custom roles, HIPAA/GDPR tools, priority support        |

> ✅ All tiers include patient consent tools and basic audit logs.

---

## 📦 Usage-Based Pricing

Usage is metered per provider account and billed monthly on top of the base subscription.

| Metric               | Free Allowance     | Overages                          |
|----------------------|--------------------|-----------------------------------|
| **Data Stored**      | 5 GB/month         | $0.20 / GB / month                |
| **Data Read**        | 1 GB/month         | $0.10 / GB                        |
| **Patient Access**   | 50/month included  | $0.50 / additional patient/month  |
| **API Requests**     | 100K/month         | $1.00 / 10,000 requests           |

> ⏱ Usage billing allows providers to scale based on actual data consumption and access needs.

---

## ⚙️ Optional Add-ons

| Add-on                         | Price                    | Description                                                  |
|--------------------------------|--------------------------|--------------------------------------------------------------|
| **Patient Chat & Consent UI**  | $10 / provider / month   | Embedded UI for messaging and dynamic data access consent    |
| **Insight Engine (Analytics)** | $99 / provider / month   | ML-powered insights on patient trends and health risks       |
| **Storage Vault**              | $0.50 / GB / month       | Optimized long-term storage for imaging and raw data files   |

---

## 👤 Patient Access Policy

- **Patients are always free**.
- Patients control who can view their data.
- All provider access is logged and auditable.
- Patients may revoke or time-limit provider access at any time.

---

## 🛡 Compliance & Enterprise Features

Included in **Enterprise Tier** only:

- HIPAA BAA agreements
- Data encryption with customer-managed keys
- Role-based access control (RBAC)
- Custom retention and deletion policies
- Private cloud or dedicated hosting

---

## 📈 Example Breakdown

**Small Clinic Example**:

- 3 providers on Pro tier: 3 × $199 = $597
- 120 patients total (70 overage): 70 × $0.50 = $35
- Data storage: 20 GB total (15 GB overage): 15 × $0.20 = $3
- Data read: 5 GB (4 GB overage): 4 × $0.10 = $0.40
- API requests: 200K (100K over): $10
- Optional Insight Engine × 2: $198

**Total Monthly Bill**: **~$843.40**

---

## 🚀 Future Ideas

- Employer-based pricing (group access for staff)
- Patient-paid upgrades for enhanced privacy or sharing controls
- Marketplace for approved third-party integrations (fitness, insurance, etc.)

---

## 📬 Questions?

This strategy is designed to evolve as we better understand our customers and usage trends. Feedback is always welcome.

Feel free to open a GitHub issue or contact the product team directly.
