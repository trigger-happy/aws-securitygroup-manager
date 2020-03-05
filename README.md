# Intro

AWS Securitygroup Manager is a Go program that lets Kubernetes cluster nodes
connect to an AWS Security Group. It can be run inside a cluster as a regular
Deployment/Pod or from outside the cluster as long as it is given a valid
Kubernetes context to use.


# Usage

The app assumes that the following environment variables have been set. The app
exits with an error message if any of them are missing:

|     Variable name        | Description                               |
|--------------------------|-------------------------------------------|
| AWS_ACCESS_KEY_ID        | AWS Access Key ID                         |
| AWS_SECRET_ACCESS_KEY    | AWS Access Key secret                     |
| AWS_VPC_ID               | AWS VPC ID                                |
| AWS_SECURITY_GROUP_ID    | AWS Security Group ID                     |
| AWS_DEFAULT_REGION       | AWS Default Region                        |
| AWS_REGION               | AWS Region                                |
| AWS_SGMANAGER_OWNER_ID   | Used to mark firewall rules for ownership |
| FROM_PORT                | Start port range for firewall rules       |
| TO_PORT                  | Ending port range for firewall rules      |
| PROTOCOL                 | Protocl (either `tcp` or `udp`)           |


## Kubernetes

The `deployment` directory of this project contains a Kustomize manifest that
you can use to deploy this application into your cluster. Simply
edit the file at `deployment/overlays/sample/secrets/env` with the desired
values and then apply the manifest to your cluster.

```bash
kubectl apply -k deployment/overlays/sample
```


# Building

To build the application, simply run the following:

```bash
go build -o aws-securitygroup-manager cmd/aws-securitygroup-manager.go
```

You can also use the provided Dockerfile to build a docker image:

```bash
docker build . -t aws-securitygroup-manager:latest
```

Note that building isn't necessary as docker images are automatically built
and pushed to docker hub under `triggerhappy/aws-securitygroup-manager:latest`.

