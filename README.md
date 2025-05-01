Monitor GH auth tokens for problems like upcoming expiration

# Usage

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

# Container

This repo publishes a lightweight container with
[`ko`](https://github.com/ko-build/ko).

## Github Actions

You can check expiration for a token in a Github Actions job directly using the
container, e.g. for a secret named `TEST_TOKEN`:

```yaml
jobs:
  test_token_expiration:
    runs-on: ubuntu-latest
    steps:
      - uses: docker://ghcr.io/fermyon/github-token-monitor:latest
        with:
          args: "--token-env-vars TEST_TOKEN"
        env:
          TEST_TOKEN: ${{ secrets.TEST_TOKEN }}
```

## Tokens Dir

You can point to a directory with `--tokens-dir`, which can be convenient when
using this as an e.g. Kubernetes CronJob to mount existing Secrets to be
checked. All files in the directory will be parsed as either bare tokens or
dockerconfig JSON.
