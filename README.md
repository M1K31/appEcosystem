# Unified Security & AI Ecosystem

A robust, offline-first ecosystem combining AI, surveillance, intrusion detection, and smart displays into a single cohesive home network.

## Architecture
The ecosystem relies on a **standalone-first** architecture: if the central coordination layer goes offline, every connected application degrades gracefully and continues to operate as an independent, fully functioning system.

- **appEcosystem**: The central service registry and event bus that ties the network together.
- **AI-for-Survival**: Offline LLM assistant (Llama 3/RAG) orchestrating active defense and system triage.
- **LogAnalysis (AegisSIEM)**: ASUS router syslog monitor and active threat mitigation system.
- **OpenEye**: AI-powered physical surveillance utilizing OpenCV for face and object recognition.
- **MagicMirror³**: The central visual hub providing UI dashboards for the entire ecosystem.

## Quickstart Setup
1. **Start the Service Registry**:
   Ensure `appEcosystem` is running to coordinate communications.
   `cd appEcosystem && python -m cli start`
2. **Launch Connected Apps**:
   Start each subsystem. They will automatically register with the ecosystem heartbeat.
3. **Verify Health**:
   Check the ecosystem monitor to ensure all systems are discovered and communicating.
   `cd appEcosystem && python -m cli status`
