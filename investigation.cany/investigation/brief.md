# Brief

**Question:** How does Parsec (installer C:\REA\parsec-windows.exe) structure its client, service and server/back-end, so we can rebuild a Parsec-like remote desktop client in Rust (eframe/egui) on top of the RustDesk engine, with an online registry of remote nodes and our own server?

**Purpose:** Learning / clean reimplementation for interoperability-style self-hosted remote desktop (SigmaDesk).

**Targets:**
- C:\REA\parsec-windows.exe

**Constraints:**
- Change files only in app/
- Don't copy Parsec branding/logos
- Static analysis only of the target

**Done when:** A Rust eframe app in app/ builds, has --screenshot, and MECHANICS.md/mechanics.json document Parsec's architecture (endpoints, ports, services, components) with sources.
