Monitor GH auth tokens for problems like upcoming expiration

```console
$ TOKEN=$(gh auth token) github-token-monitor --token-env-vars TOKEN
Checking "TOKEN"...
Token user login: your-github-username
Token expiration: NONE
Rate limit usage: 6 / 5000 (~0%)
OAuth scopes: gist, read:org, repo, workflow

$ OLD_TOKEN="<some expiring token>" github-token-monitor --token-env-vars OLD_TOKEN
Checking "OLD_TOKEN"...
Token user login: your-github-username
Token expiration: 2025-07-09 21:27:10 +0000 UTC (9.1 days)
WARNING: Expiring soon!
Rate limit usage: 9 / 5000 (~0%)
OAuth scopes: read:packages

Error: checks failed for token(s): OLD_TOKEN
exit status 1
```

Also supports pointing to a directory with `--tokens-dir`, which can be
convenient when using this as an e.g. Kubernetes CronJob to mount existing
Secrets to be checked. The files in this directory can be either bare tokens
or dockerconfig JSON.
