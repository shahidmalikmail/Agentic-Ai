# EKS Monitoring MCP Server

This MCP server exposes Kubernetes and EKS monitoring tools for an AI agent.

## Included tools

- `describe_eks_cluster`
- `get_nodes`
- `get_pods`
- `get_services`
- `get_ingresses`
- `get_hpas`
- `get_events`
- `get_cluster_health_summary`

## Setup

1. Activate your Python environment.
2. Install dependencies:

   pip install -r AI-Agent/requirements.txt

3. Export the cluster config:

   export KUBECONFIG=/path/to/your/kubeconfig
   export EKS_CLUSTER_NAME=your-cluster-name
   export AWS_REGION=us-east-1
   export EKS_CONTEXT=your-cluster-context

4. Start the MCP server:

   python AI-Agent/eks_monitor_server.py

## How this is used

Your AI agent can call the MCP tools to inspect nodes, pods, services, ingresses, HPA objects, recent events, and cluster health.

Example prompt:

- "Check if any EKS nodes are NotReady"
- "List unhealthy pods in the production namespace"
- "Show me ingress and HPA health for the cluster"
- "Summarize the overall cluster health"
