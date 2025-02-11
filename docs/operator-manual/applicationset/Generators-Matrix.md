# Matrix Generator

The Matrix generator combines the parameters generated by two child generators, iterating through every combination of each generator's generated parameters.

By combining both generators parameters, to produce every possible combination, this allows you to gain the intrinsic properties of both generators. For example, a small subset of the many possible use cases include:

- *SCM Provider Generator + Cluster Generator*: Scanning the repositories of a GitHub organization for application resources, and targeting those resources to all available clusters.
- *Git File Generator + List Generator*: Providing a list of applications to deploy via configuration files, with optional configuration options, and deploying them to a fixed list of clusters.
- *Git Directory Generator + Cluster Decision Resource Generator*: Locate application resources contained within folders of a Git repository, and deploy them to a list of clusters provided via an external custom resource.
- And so on...

Any set of generators may be used, with the combined values of those generators inserted into the `template` parameters, as usual.

## Example: Git Directory generator + Cluster generator

As an example, imagine that we have two clusters:

- A `staging` cluster (at `https://1.2.3.4`)
- A `production` cluster (at `https://2.4.6.8`)

And our application YAMLs are defined in a Git repository:

- Argo Workflows controller (examples/git-generator-directory/cluster-addons/argo-workflows)
- Prometheus operator (/examples/git-generator-directory/cluster-addons/prometheus-operator)

Our goal is to deploy both applications onto both clusters, and, more generally, in the future to automatically deploy new applications in the Git repository, and to new clusters defined within Argo CD, as well.

For this we will use the Matrix generator, with the Git and the Cluster as child generators:

```yaml
apiVersion: argoproj.io/v1alpha1
kind: ApplicationSet
metadata:
  name: cluster-git
spec:
  generators:
    # matrix 'parent' generator
    - matrix:
        generators:
          # git generator, 'child' #1
          - git:
              repoURL: https://github.com/argoproj/argo-cd.git
              revision: HEAD
              directories:
                - path: applicationset/examples/matrix/cluster-addons/*
          # cluster generator, 'child' #2
          - clusters:
              selector:
                matchLabels:
                  argocd.argoproj.io/secret-type: cluster
  template:
    metadata:
      name: '{{path.basename}}-{{name}}'
    spec:
      project: '{{metadata.labels.environment}}'
      source:
        repoURL: https://github.com/argoproj/argo-cd.git
        targetRevision: HEAD
        path: '{{path}}'
      destination:
        server: '{{server}}'
        namespace: '{{path.basename}}'
```

First, the Git directory generator will scan the Git repository, discovering directories under the specified path. It discovers the argo-workflows and prometheus-operator applications, and produces two corresponding sets of parameters:
```yaml
- path: /examples/git-generator-directory/cluster-addons/argo-workflows
  path.basename: argo-workflows

- path: /examples/git-generator-directory/cluster-addons/prometheus-operator
  path.basename: prometheus-operator
```

Next, the Cluster generator scans the [set of clusters defined in Argo CD](Generators-Cluster.md), finds the staging and production cluster secrets, and produce two corresponding sets of parameters:
```yaml
- name: staging
  server: https://1.2.3.4

- name: production
  server: https://2.4.6.8
```

Finally, the Matrix generator will combine both sets of outputs, and produce:
```yaml
- name: staging
  server: https://1.2.3.4
  path: /examples/git-generator-directory/cluster-addons/argo-workflows
  path.basename: argo-workflows

- name: staging
  server: https://1.2.3.4
  path: /examples/git-generator-directory/cluster-addons/prometheus-operator
  path.basename: prometheus-operator

- name: production
  server: https://2.4.6.8
  path: /examples/git-generator-directory/cluster-addons/argo-workflows
  path.basename: argo-workflows

- name: production
  server: https://2.4.6.8
  path: /examples/git-generator-directory/cluster-addons/prometheus-operator
  path.basename: prometheus-operator
```
(*The full example can be found [here](https://github.com/argoproj/argo-cd/tree/master/applicationset/examples/matrix).*)

## Using Parameters from one child generator in another child generator

The Matrix generator allows using the parameters generated by one child generator inside another child generator. 
Below is an example that uses a git-files generator in conjunction with a cluster generator.

```yaml
apiVersion: argoproj.io/v1alpha1
kind: ApplicationSet
metadata:
  name: cluster-git
spec:
  generators:
    # matrix 'parent' generator
    - matrix:
        generators:
          # git generator, 'child' #1
          - git:
              repoURL: https://github.com/argoproj/applicationset.git
              revision: HEAD
              files:
                - path: "examples/git-generator-files-discovery/cluster-config/**/config.json"
          # cluster generator, 'child' #2
          - clusters:
              selector:
                matchLabels:
                  argocd.argoproj.io/secret-type: cluster
                  kubernetes.io/environment: '{{path.basename}}'
  template:
    metadata:
      name: '{{name}}-guestbook'
    spec:
      project: default
      source:
        repoURL: https://github.com/argoproj/applicationset.git
        targetRevision: HEAD
        path: "examples/git-generator-files-discovery/apps/guestbook"
      destination:
        server: '{{server}}'
        namespace: guestbook
```
Here is the corresponding folder structure for the git repository used by the git-files generator:

```
├── apps
│   └── guestbook
│       ├── guestbook-ui-deployment.yaml
│       ├── guestbook-ui-svc.yaml
│       └── kustomization.yaml
├── cluster-config
│   └── engineering
│       ├── dev
│       │   └── config.json
│       └── prod
│           └── config.json
└── git-generator-files.yaml
```
In the above example, the `{{path.basename}}` parameters produced by the git-files generator will resolve to `dev` and `prod`.
In the 2nd child generator, the label selector with label `kubernetes.io/environment: {{path.basename}}` will resolve with the values produced by the first child generator's parameters (`kubernetes.io/environment: prod` and `kubernetes.io/environment: dev`). 

So in the above example, clusters with the label `kubernetes.io/environment: prod` will have only prod-specific configuration (ie. `prod/config.json`) applied to it, wheres clusters
with the label `kubernetes.io/environment: dev` will have only dev-specific configuration (ie. `dev/config.json`)

## Restrictions

1. The Matrix generator currently only supports combining the outputs of only two child generators (eg does not support generating combinations for 3 or more).
1. You should specify only a single generator per array entry, eg this is not valid:
```yaml
- matrix:
    generators:
     - list: # (...)
       git: # (...)
```
    - While this *will* be accepted by Kubernetes API validation, the controller will report an error on generation. Each generator should be specified in a separate array element, as in the examples above.
1. The Matrix generator does not currently support [`template` overrides](Template.md#generator-templates) specified on child generators, eg this `template` will not be processed:
```yaml
- matrix:
    generators:
      - list:
          elements:
            - # (...)
          template: { } # Not processed
```
1. Combination-type generators (matrix or merge) can only be nested once. For example, this will not work:
```yaml
- matrix:
    generators:
      - matrix:
          generators:
            - matrix:  # This third level is invalid.
                generators:
                  - list:
                      elements:
                        - # (...)
```
1. When using parameters from one child generator inside another child generator, the child generator that *consumes* the parameters **must come after** the child generator that *produces* the parameters.
For example, the below example would be invalid (cluster-generator must come after the git-files generator):
```yaml
- matrix:
    generators:
      # cluster generator, 'child' #1
      - clusters:
          selector:
            matchLabels:
              argocd.argoproj.io/secret-type: cluster
              kubernetes.io/environment: '{{path.basename}}' # {{path.basename}} is produced by git-files generator
      # git generator, 'child' #2
      - git:
          repoURL: https://github.com/argoproj/applicationset.git
          revision: HEAD
          files:
            - path: "examples/git-generator-files-discovery/cluster-config/**/config.json"
```
1. You cannot have both child generators consuming parameters from each another. In the example below, the cluster generator is consuming the `{{path.basename}}` parameter produced by the git-files generator, whereas the git-files generator is consuming the `{{name}}` parameter produced by the cluster generator. This will result in a circular dependency, which is invalid.
```yaml
- matrix:
    generators:
      # cluster generator, 'child' #1
      - clusters:
          selector:
            matchLabels:
              argocd.argoproj.io/secret-type: cluster
              kubernetes.io/environment: '{{path.basename}}' # {{path.basename}} is produced by git-files generator
      # git generator, 'child' #2
      - git:
          repoURL: https://github.com/argoproj/applicationset.git
          revision: HEAD
          files:
            - path: "examples/git-generator-files-discovery/cluster-config/engineering/{{name}}**/config.json" # {{name}} is produced by cluster generator
```

