# Disclosure of AI Agent Toolsets as a Prompt Injection Vulnerability

## Prompt Injection Risks from Disclosing AI Agent Toolsets

### Background: AI Agents and Tool Use

Large Language Model (LLM) based AI agents increasingly integrate external tools (plugins, APIs, or system commands) to extend their capabilities beyond text generation. Frameworks like the ReAct prompt pattern allow AIs to interact with external systems. By equipping an AI with tool use, developers enable powerful new functionalities – for example, an agent can search the internet, read/write files, send emails, or run code in response to user instructions.

However, once an AI can take actions on a system or call external APIs, a maliciously crafted prompt or input can potentially trick the agent into performing unintended or harmful operations.

One foundational vulnerability class in this context is **prompt injection** – where an attacker supplies input that subverts the agent’s instructions or intentions. Initially seen as playful or low-risk, prompt injection becomes “genuinely dangerous” when applied to agents with tool capabilities. An injected instruction could drive the AI to invoke powerful tools in an unintended way.

*References: [simonwillison.net](https://simonwillison.net), [venturebeat.com](https://venturebeat.com)*

---

### Vulnerability Overview: Toolset Disclosure

An often-overlooked aspect of this vulnerability is the disclosure of the AI agent’s available toolset. If an AI assistant explicitly reveals which tools or plugins it has access to (for instance, through documentation or in response to user queries), it enables attackers to target those tools directly.

Many tool-using AI systems provide such information by design. For example, the Auto-GPT agent includes a list of functions in its prompt context:
