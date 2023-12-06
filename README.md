# cedar-rbac

Sample rbac implementation with cedar

Kubernetes 風に `admin` ロールを持った `Alice` と `viewer` ロールを持った `Bob` という設定で `nginx-pod` という `Pod` を操作する設定です。

```
$ cedar-rbac Alice describe nginx-pod
Hello Alice! You can describe nginx-pod.

$ cedar-rbac Bob describe nginx-pod
Hello Bob! You can describe nginx-pod.

$ cedar-rbac Alice delete nginx-pod
Hello Alice! You can delete nginx-pod.

$ cedar-rbac Bob delete nginx-pod
Authorization Denied
```

https://sogo.dev/posts/2023/12/cedar-rbac
