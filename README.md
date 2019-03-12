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

By default, `ktrial` prints the decisions in a human-readable format:

```
----
Operation : CREATE
Kind      : extensions/v1beta1/Ingress
Namespace : torin-opa-test
Name      : 
Username  : minikube-user
Groups    : [system:masters system:authenticated]
Object    :
  {
    "metadata": {
      "name": "ingress-bad",
      "namespace": "torin-opa-test",
      "uid": "82e18de3-4414-11e9-a7c0-08002716a967",
      "generation": 1,
      "creationTimestamp": "2019-03-11T15:44:09Z"
    },
    "spec": {
      "rules": [
        {
          "host": "acmecorp.com",
          "http": {
            "paths": [
              {
                "backend": {
                  "serviceName": "nginx",
                  "servicePort": 80
                }
              }
            ]
          }
        }
      ]
    },
    "status": {
      "loadBalancer": {}
    }
  }
Duration  : 2ms
Decision  : DENY
Reason    : invalid ingress host "acmecorp.com"
```

If you run `ktrial` with `--format=json` it will print the decisions
in JSON which is useful for test purposes.

## Cleaning up

If something goes wrong you can disable the webhook by running:

```
kubectl delete validatingwebhookconfigurations $USER-opa-webhook
```

## TODO

* Add support for specifying OPA image version(s).
* Add option to disable test namespace instantiation.
* Add support for specifying inventory dependencies manually.
* Add support for mutating policies.
* Automatically create context for test namespace and set current-context.
