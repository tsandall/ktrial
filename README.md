# ktrial

Trial OPA Kubernetes admission control policies.

## Overview

`ktrial` provides a command-line utility for testing OPA admission
control policies in a live Kubernetes cluster. `ktrial` is useful
when you need to:

* Collect input data for offline testing
* Quickly experiment with a policy on a live cluster

`ktrial` automates a common workflow for experimenting with OPA
admission control policies. `ktrial` will:

* Install OPA into a temporary namespace on your Kubernetes cluster
* Load policy and data files into OPA via volume mounts
* Discovery Kubernetes resource dependencies and configure `kube-mgmt` accordingly
* Register OPA as an admission controller
* Display admission control decisions being made by OPA

## Building and Installing

Run `go get -u github.com/tsandall/ktrial` to install `ktrial` into
your `$GOPATH`.

Run `go build .` inside this directory to produce the `ktrial`
executable.

## Getting Started

Create a simple admission control policy:

**file.rego**:

```
package test

deny["bad deployment image"] {
    input.request.kind.kind = "Deployment"
    input.request.object.spec.template.spec.containers[_].image = "nginx"
}
```

Run `ktrial file.rego` to deploy the admission control policy.

> By default, `ktrial` will create two namespaces: `$USER-opa` and
> `$USER-opa-test`. The admission controller is deployed into the
> `$USER-opa` namespace and the webhook is configured to check all
> operations on all resources in the `$USER-opa-test`
> namespace. Because the webhook is configured to check all operations
> on all resources, you will see decisions for cluster-scoped
> resources (Kubernetes does not filter these.)

Run `kubectl -n $USER-opa-test run --image=nginx nginx` to exercise
the admission control policy.

## Policy Format

### `deny[info]` Rules

By default `ktrial` identifies `deny` rules inside the supplied policy
files and configures the admission controller to evaluate them. If you
don't supply a `system.main` rule, `ktrial` will generate one for
you.

### Kubernetes Inventory

`ktrial` analyzes policies to find dependencies on
Kubernetes inventory, e.g., namespaces, ingresses, etc. `ktrial` will
automatically configure the `kube-mgmt` container in the deployment to
replicate inventory dependencies into OPA. When `ktrial` deploys the
admission controller it logs the resource dependencies that it
identifies:

```
Detected namespace-scoped resources : [extensions/v1beta1/ingresses]
Detected cluster-scoped resources   : [v1/namespaces]
```

## Output

`ktrial` prints the `input`, `result`, and `metrics` keys from the OPA decision
log to the console as JSON:

```json
{
  "input": {
    "kind": "AdmissionReview",
    "apiVersion": "admission.k8s.io/v1beta1",
    "request": {
      "uid": "fca7da4b-5d5b-4741-8c32-59700a4670f3",
      "kind": {
        "group": "",
        "version": "v1",
        "kind": "Event"
      },
      "resource": {
        "group": "",
        "version": "v1",
        "resource": "events"
      },
      "namespace": "torin-opa-test",
      "operation": "CREATE",
      "userInfo": {
        "username": "system:node:kind-control-plane",
        "groups": [
          "system:nodes",
          "system:authenticated"
        ]
      },
      "object": {
        "apiVersion": "v1",
        "count": 1,
        "eventTime": null,
        "firstTimestamp": "2019-08-13T15:06:37Z",
        "involvedObject": {
          "apiVersion": "v1",
          "fieldPath": "spec.containers{nginx}",
          "kind": "Pod",
          "name": "nginx-7bb7cd8db5-lk2tm",
          "namespace": "torin-opa-test",
          "resourceVersion": "910",
          "uid": "808cf273-1f6f-4c9b-9259-fdfd803d48b6"
        },
        "kind": "Event",
        "lastTimestamp": "2019-08-13T15:06:37Z",
        "message": "Started container nginx",
        "metadata": {
          "creationTimestamp": "2019-08-13T15:06:37Z",
          "name": "nginx-7bb7cd8db5-lk2tm.15ba83db166bcfb4",
          "namespace": "torin-opa-test",
          "uid": "e157b4d9-636c-4dfb-9689-6ce39e049909"
        },
        "reason": "Started",
        "reportingComponent": "",
        "reportingInstance": "",
        "source": {
          "component": "kubelet",
          "host": "kind-control-plane"
        },
        "type": "Normal"
      },
      "oldObject": null
    }
  },
  "result": {
    "kind": "AdmissionReview",
    "apiVersion": "admission.k8s.io/v1beta1",
    "response": {
      "uid": "",
      "allowed": true
    }
  },
  "metrics": {
    "timer_rego_module_compile_ns": 221,
    "timer_rego_module_parse_ns": 521,
    "timer_rego_query_compile_ns": 119925,
    "timer_rego_query_eval_ns": 102984,
    "timer_rego_query_parse_ns": 219307,
    "timer_server_handler_ns": 650534
  }
}
```

## Cleaning up

If something goes wrong you can disable the webhook by running:

```
kubectl delete validatingwebhookconfigurations $USER-opa-webhook
```

## TODO

* Add support for specifying OPA image version(s).
* Add option to disable test namespace instantiation.
* Add support for specifying inventory dependencies manually.
* Add support for discovering mutating policies.
* Automatically create context for test namespace and set current-context.
